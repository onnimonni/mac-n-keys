import ArgumentParser
import BigInt
import Darwin
import Foundation
import Lib
import Security

struct PasswordsGroup: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "passwords",
    abstract: "Access Apple Passwords with Touch ID",
    subcommands: [
      PasswordsAuthCommand.self,
      PasswordsGetCommand.self,
      PasswordsListCommand.self,
      PasswordsOTPCommand.self,
    ]
  )
}

struct PasswordsAuthCommand: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "auth",
    abstract: "Authenticate with Passwords.app (SRP handshake)"
  )

  @Option(help: "Daemon socket path (default: ~/.mac-n-keys/daemon.sock)")
  var socket: String?

  // MARK: - Rate limiting (stored in Keychain to resist tampering)

  private static let maxAttempts = 5
  private static let backoffBase: TimeInterval = 300  // 5 minutes

  private static let rateLimitService = "build.flaky.mac-n-keys.auth.ratelimit"
  private static let rateLimitAccount = "attempts"

  private struct RateLimitData: Codable {
    var failedAttempts: Int
    var lastFailTime: TimeInterval
  }

  private func loadRateLimitData() -> RateLimitData? {
    let query = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.rateLimitService,
      kSecAttrAccount: Self.rateLimitAccount,
      kSecReturnData: true,
    ] as [CFString: Any] as CFDictionary
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query, &result)
    guard status == errSecSuccess, let data = result as? Data else { return nil }
    return try? JSONDecoder().decode(RateLimitData.self, from: data)
  }

  private func saveRateLimitData(_ data: RateLimitData) {
    guard let encoded = try? JSONEncoder().encode(data) else { return }
    let deleteQuery = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.rateLimitService,
      kSecAttrAccount: Self.rateLimitAccount,
    ] as [CFString: Any] as CFDictionary
    SecItemDelete(deleteQuery)

    let addQuery = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.rateLimitService,
      kSecAttrAccount: Self.rateLimitAccount,
      kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecValueData: encoded,
    ] as [CFString: Any] as CFDictionary
    SecItemAdd(addQuery, nil)
  }

  private func checkRateLimit() throws {
    guard let rl = loadRateLimitData() else { return }
    guard rl.failedAttempts >= Self.maxAttempts else { return }
    guard rl.lastFailTime > 0 else { return }

    // Exponential backoff: 5min * 2^(attempts - maxAttempts)
    let exponent = min(rl.failedAttempts - Self.maxAttempts, 6)  // cap at ~5h
    let cooldown = Self.backoffBase * pow(2.0, Double(exponent))
    let elapsed = Date().timeIntervalSince1970 - rl.lastFailTime

    if elapsed < cooldown {
      let remaining = Int(cooldown - elapsed)
      throw PasswordsAuthError.rateLimited(remaining)
    }
  }

  private func recordFailure() {
    let current = loadRateLimitData() ?? RateLimitData(failedAttempts: 0, lastFailTime: 0)
    saveRateLimitData(RateLimitData(
      failedAttempts: current.failedAttempts + 1,
      lastFailTime: Date().timeIntervalSince1970
    ))
  }

  private func resetRateLimit() {
    let query = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.rateLimitService,
      kSecAttrAccount: Self.rateLimitAccount,
    ] as [CFString: Any] as CFDictionary
    SecItemDelete(query)
  }

  /// Read a line from stdin with terminal echo disabled.
  private func readSecure() -> String? {
    var oldTerm = termios()
    tcgetattr(STDIN_FILENO, &oldTerm)
    var newTerm = oldTerm
    newTerm.c_lflag &= ~UInt(ECHO)
    tcsetattr(STDIN_FILENO, TCSANOW, &newTerm)
    defer {
      tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm)
      print("")  // newline after hidden input
    }
    return readLine()
  }

  func run() async throws {
    try checkRateLimit()

    let socketPath = socket ?? DaemonConnection.defaultSocketPath
    let session = try SRPSession.create(useBase64: true)

    // Request challenge
    let challengeMsg = try PasswordsMessages.requestChallenge(session: session)
    let challengeResp = try DaemonConnection.sendMessage(challengeMsg, socketPath: socketPath)

    guard let payload = challengeResp["payload"] as? [String: Any],
      let pakeBase64 = payload["PAKE"] as? String,
      let pakeData = Data(base64Encoded: pakeBase64),
      let pake = try? JSONSerialization.jsonObject(with: pakeData) as? [String: Any]
    else {
      throw PasswordsAuthError.invalidServerHello
    }

    guard let bStr = pake["B"] as? String, let sStr = pake["s"] as? String else {
      throw PasswordsAuthError.invalidServerHello
    }

    let B = BigUInt(session.deserialize(bStr))
    let s = BigUInt(session.deserialize(sStr))
    try session.setServerPublicKey(B, salt: s)

    // Prompt for PIN (with echo disabled so digits aren't visible)
    print("Enter the 6-digit code from Passwords.app: ", terminator: "")
    fflush(stdout)
    guard let pin = readSecure()?.trimmingCharacters(in: .whitespacesAndNewlines) else {
      throw PasswordsAuthError.noPinProvided
    }

    // Verify challenge
    let newKey = try session.setSharedKey(password: pin)
    let m = try session.computeM()
    let verifyMsg = try PasswordsMessages.verifyChallenge(session: session, m: m)
    let verifyResp = try DaemonConnection.sendMessage(verifyMsg, socketPath: socketPath)

    guard let verifyPayload = verifyResp["payload"] as? [String: Any],
      let verifyPakeBase64 = verifyPayload["PAKE"] as? String,
      let verifyPakeData = Data(base64Encoded: verifyPakeBase64),
      let verifyPake = try? JSONSerialization.jsonObject(with: verifyPakeData) as? [String: Any]
    else {
      throw PasswordsAuthError.verificationFailed
    }

    if let errCode = verifyPake["ErrCode"] as? Int, errCode != 0 {
      if errCode == 1 {
        recordFailure()
        throw PasswordsAuthError.incorrectPin
      }
      recordFailure()
      throw PasswordsAuthError.verificationFailed
    }

    // Verify HAMK (server verifier)
    let verifier = try session.computeServerVerifier(m)
    if let hamkStr = verifyPake["HAMK"] as? String {
      let serverHAMK = BigUInt(session.deserialize(hamkStr))
      let clientHAMK = BigUInt(verifier)
      if serverHAMK != clientHAMK {
        recordFailure()
        throw PasswordsAuthError.hamkMismatch
      }
    }

    // Success — reset rate limit
    resetRateLimit()

    // Save session
    let keyData = session.bigUIntToData(newKey)
    try SessionKeychain.save(username: session.username, sharedKey: keyData, socketPath: socketPath)
    print("Authenticated successfully. Session saved to Keychain.")
  }
}

enum PasswordsAuthError: LocalizedError {
  case invalidServerHello
  case noPinProvided
  case incorrectPin
  case verificationFailed
  case hamkMismatch
  case rateLimited(Int)

  var errorDescription: String? {
    switch self {
    case .invalidServerHello: "Invalid server hello response"
    case .noPinProvided: "No PIN provided"
    case .incorrectPin: "Incorrect PIN"
    case .verificationFailed: "Verification failed"
    case .hamkMismatch: "HAMK mismatch"
    case .rateLimited(let seconds): "Too many failed attempts. Try again in \(seconds)s"
    }
  }
}
