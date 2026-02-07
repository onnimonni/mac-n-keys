import BigInt
import CryptoKit
import Foundation

/// SRP session implementing RFC 2945 / RFC 5054 with 3072-bit group.
/// Ported from apw/src/srp.ts.
public class SRPSession: @unchecked Sendable {

  public let username: String
  private let clientPrivateKey: BigUInt
  private let useBase64: Bool
  private let lock = NSLock()

  // Set during handshake — access guarded by lock
  private var _serverPublicKey: BigUInt?
  private var _salt: BigUInt?
  private var _sharedKey: BigUInt?

  public var serverPublicKey: BigUInt? { lock.withLock { _serverPublicKey } }
  public var salt: BigUInt? { lock.withLock { _salt } }
  public var sharedKey: BigUInt? { lock.withLock { _sharedKey } }

  private init(username: Data, clientPrivateKey: BigUInt, useBase64: Bool = false) {
    self.clientPrivateKey = clientPrivateKey
    self.useBase64 = useBase64
    if useBase64 {
      self.username = username.base64EncodedString()
    } else {
      self.username = "0x" + username.hexString
    }
  }

  private init(rawUsername: String, clientPrivateKey: BigUInt, sharedKey: BigUInt, useBase64: Bool) {
    self.username = rawUsername
    self.clientPrivateKey = clientPrivateKey
    self.useBase64 = useBase64
    self._sharedKey = sharedKey
  }

  /// Create a new SRP session with random credentials.
  public static func create(useBase64: Bool = false) throws -> SRPSession {
    var usernameBytes = [UInt8](repeating: 0, count: 16)
    guard SecRandomCopyBytes(kSecRandomDefault, 16, &usernameBytes) == errSecSuccess else {
      throw SRPError.randomGenerationFailed
    }
    var privateKeyBytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, &privateKeyBytes) == errSecSuccess else {
      throw SRPError.randomGenerationFailed
    }
    let clientPrivateKey = BigUInt(Data(privateKeyBytes))
    return SRPSession(
      username: Data(usernameBytes), clientPrivateKey: clientPrivateKey, useBase64: useBase64)
  }

  /// Restore a session from saved state.
  public static func restore(username: String, sharedKey: BigUInt, useBase64: Bool = false)
    -> SRPSession
  {
    SRPSession(
      rawUsername: username, clientPrivateKey: BigUInt(0), sharedKey: sharedKey,
      useBase64: useBase64)
  }

  /// Client public key: A = g^a mod N
  public var clientPublicKey: BigUInt {
    SRPSession.powermod(
      SRPConstants.groupGenerator, clientPrivateKey, SRPConstants.groupPrime)
  }

  // MARK: - Serialization

  public func serialize(_ data: Data, prefix: Bool = true) -> String {
    if useBase64 {
      return data.base64EncodedString()
    }
    return (prefix ? "0x" : "") + data.hexString
  }

  public func deserialize(_ data: String) -> Data {
    if useBase64 {
      return Data(base64Encoded: data) ?? Data()
    }
    let hex = data.hasPrefix("0x") ? String(data.dropFirst(2)) : data
    var bytes = [UInt8]()
    var idx = hex.startIndex
    while idx < hex.endIndex {
      let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
      if let byte = UInt8(hex[idx..<next], radix: 16) {
        bytes.append(byte)
      }
      idx = next
    }
    return Data(bytes)
  }

  // MARK: - Handshake

  public func setServerPublicKey(_ B: BigUInt, salt s: BigUInt) throws {
    guard B % SRPConstants.groupPrime != 0 else {
      throw SRPError.invalidServerPublicKey
    }
    lock.withLock {
      _serverPublicKey = B
      _salt = s
    }
  }

  /// Derive shared key from password. Returns shared key for storage.
  public func setSharedKey(password: String) throws -> BigUInt {
    let (B, s) = try lock.withLock { () -> (BigUInt, BigUInt) in
      guard let B = _serverPublicKey else { throw SRPError.missingServerPublicKey }
      guard let s = _salt else { throw SRPError.missingSalt }
      return (B, s)
    }

    let N = SRPConstants.groupPrime
    let g = SRPConstants.groupGenerator
    let padLen = SRPConstants.groupPrimeBytes
    let A = clientPublicKey

    // u = SHA256(pad(A) | pad(B))
    let u = BigUInt(sha256(pad(bigUIntToData(A), to: padLen) + pad(bigUIntToData(B), to: padLen)))

    // k = SHA256(N | pad(g))
    let k = BigUInt(
      sha256(bigUIntToData(N) + pad(bigUIntToData(g), to: padLen)))

    // x = SHA256(s | SHA256(username:password))
    let innerHash = sha256(Data((username + ":" + password).utf8))
    let x = BigUInt(sha256(bigUIntToData(s) + innerHash))

    // S = (B - k * g^x) ^ (a + u * x) mod N
    let gx = SRPSession.powermod(g, x, N)
    var base = (B + N * 10) - (k * gx % N)  // add N*10 to avoid underflow
    base = base % N
    let exp = clientPrivateKey + u * x
    let premasterSecret = SRPSession.powermod(base, exp, N)

    let computed = BigUInt(sha256(bigUIntToData(premasterSecret)))
    lock.withLock { _sharedKey = computed }
    return computed
  }

  /// Compute M for RFC verification.
  public func computeM() throws -> Data {
    let (B, s, K) = try lock.withLock { () -> (BigUInt, BigUInt, BigUInt) in
      guard let B = _serverPublicKey else { throw SRPError.missingServerPublicKey }
      guard let s = _salt else { throw SRPError.missingSalt }
      guard let K = _sharedKey else { throw SRPError.missingSharedKey }
      return (B, s, K)
    }

    let N = SRPConstants.groupPrime
    let g = SRPConstants.groupGenerator
    let padLen = SRPConstants.groupPrimeBytes

    let hashN = sha256(bigUIntToData(N))
    let hashG = sha256(pad(bigUIntToData(g), to: padLen))
    let xorNG = Data(zip(hashN, hashG).map { $0 ^ $1 })
    let hashI = sha256(Data(username.utf8))

    return sha256(
      xorNG + hashI + bigUIntToData(s)
        + bigUIntToFixedData(clientPublicKey, size: padLen)
        + bigUIntToFixedData(B, size: padLen)
        + bigUIntToFixedData(K, size: 32))
  }

  /// Compute server verifier: SHA256(A || M || K).
  public func computeServerVerifier(_ m: Data) throws -> Data {
    let K = try lock.withLock { () -> BigUInt in
      guard let K = _sharedKey else { throw SRPError.missingSharedKey }
      return K
    }
    let padLen = SRPConstants.groupPrimeBytes
    return sha256(
      bigUIntToFixedData(clientPublicKey, size: padLen) + m + bigUIntToFixedData(K, size: 32))
  }

  // MARK: - Encryption

  /// Get AES-256-GCM encryption key from shared key (full 32-byte SHA-256 hash).
  public func encryptionKeyData() throws -> Data {
    let K = try lock.withLock { () -> BigUInt in
      guard let K = _sharedKey else { throw SRPError.missingSharedKey }
      return K
    }
    // Shared key is SHA-256 output (32 bytes). Pad to 32 to handle leading-zero stripping.
    return pad(bigUIntToData(K), to: 32)
  }

  /// Encrypt raw data with AES-256-GCM using the session encryption key.
  public func encrypt(_ data: Data) throws -> Data {
    let key = try SymmetricKey(data: encryptionKeyData())
    var iv = [UInt8](repeating: 0, count: 12)
    guard SecRandomCopyBytes(kSecRandomDefault, 12, &iv) == errSecSuccess else {
      throw SRPError.randomGenerationFailed
    }
    let nonce = try AES.GCM.Nonce(data: Data(iv))
    let sealed = try AES.GCM.seal(data, using: key, nonce: nonce)
    // Client→server wire format: ciphertext + tag + iv (iv at end)
    return sealed.ciphertext + sealed.tag + Data(iv)
  }

  /// Encrypt a JSON dictionary with AES-GCM using the session encryption key.
  public func encrypt(_ object: [String: Any]) throws -> Data {
    let jsonData = try JSONSerialization.data(withJSONObject: object)
    return try encrypt(jsonData)
  }

  /// Decrypt data with AES-256-GCM.
  public func decrypt(_ data: Data) throws -> Data {
    let key = try SymmetricKey(data: encryptionKeyData())
    // Server→client wire format: iv (12 bytes) + ciphertext + tag (16 bytes)
    let iv = data.prefix(12)
    let rest = data.dropFirst(12)
    let nonce = try AES.GCM.Nonce(data: iv)
    let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: rest.dropLast(16), tag: rest.suffix(16))
    return try AES.GCM.open(sealedBox, using: key)
  }

  // MARK: - Helpers

  private func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
  }

  public func bigUIntToData(_ value: BigUInt) -> Data {
    value.serialize()
  }

  /// Serialize BigUInt to fixed-width Data, zero-padded on the left.
  public func bigUIntToFixedData(_ value: BigUInt, size: Int) -> Data {
    pad(bigUIntToData(value), to: size)
  }

  func pad(_ data: Data, to length: Int) -> Data {
    if data.count >= length { return Data(data.prefix(length)) }
    var padded = Data(repeating: 0, count: length)
    padded.replaceSubrange((length - data.count)..<length, with: data)
    return padded
  }

  static func powermod(_ base: BigUInt, _ exp: BigUInt, _ mod: BigUInt) -> BigUInt {
    base.power(exp, modulus: mod)
  }
}

public enum SRPError: LocalizedError {
  case invalidServerPublicKey
  case missingServerPublicKey
  case missingSalt
  case missingSharedKey
  case randomGenerationFailed

  public var errorDescription: String? {
    switch self {
    case .invalidServerPublicKey: "Invalid server public key"
    case .missingServerPublicKey: "Missing server public key"
    case .missingSalt: "Missing salt"
    case .missingSharedKey: "Missing shared key"
    case .randomGenerationFailed: "Secure random generation failed"
    }
  }
}
