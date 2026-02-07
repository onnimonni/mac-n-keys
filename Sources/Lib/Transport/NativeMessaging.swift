import Foundation

/// Communicates with PasswordManagerBrowserExtensionHelper via Native Messaging protocol.
/// The helper uses 4-byte length prefix + JSON over stdio.
public class NativeMessaging {

  private let process: Foundation.Process
  private let stdinPipe: Pipe
  private let stdoutPipe: Pipe

  /// Find and launch the PasswordManagerBrowserExtensionHelper.
  public init() throws {
    let helperPath = try NativeMessaging.findHelperPath()
    process = Foundation.Process()
    process.executableURL = URL(fileURLWithPath: helperPath)
    process.arguments = ["."]
    stdinPipe = Pipe()
    stdoutPipe = Pipe()
    process.standardInput = stdinPipe
    process.standardOutput = stdoutPipe
    try process.run()
  }

  deinit {
    process.terminate()
  }

  /// Send a message and receive a response.
  public func sendMessage(_ message: Any) throws -> Any {
    let jsonData = try JSONSerialization.data(withJSONObject: message)
    // Write 4-byte length prefix (little-endian per Chrome NativeMessaging spec) + JSON
    var length = UInt32(jsonData.count).littleEndian
    let lengthData = unsafe Data(bytes: &length, count: 4)
    stdinPipe.fileHandleForWriting.write(lengthData + jsonData)

    // Read 4-byte length prefix from response
    let responseLengthData = stdoutPipe.fileHandleForReading.readData(ofLength: 4)
    guard responseLengthData.count == 4 else {
      throw TransportError.helperCommunicationFailed
    }
    let responseLength = UInt32(littleEndian: responseLengthData.withUnsafeBytes { $0.load(as: UInt32.self) })
    guard responseLength > 0, responseLength < 10_000_000 else {
      throw TransportError.helperCommunicationFailed
    }
    let responseData = stdoutPipe.fileHandleForReading.readData(ofLength: Int(responseLength))
    return try JSONSerialization.jsonObject(with: responseData)
  }

  /// Trusted path prefixes for the helper binary.
  /// Only system-protected paths — /Applications/ is excluded because it is
  /// admin-writable and any installed app would pass the check.
  private static let trustedPrefixes = [
    "/System/",
    "/Library/",
  ]

  /// Discover the helper path from NativeMessagingHosts manifests.
  /// Validates the resolved path starts with a trusted prefix.
  static func findHelperPath() throws -> String {
    let candidates = [
      "/Library/Application Support/Mozilla/NativeMessagingHosts/com.apple.passwordmanager.json",
      "/Library/Google/Chrome/NativeMessagingHosts/com.apple.passwordmanager.json",
    ]
    for path in candidates {
      if FileManager.default.fileExists(atPath: path) {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        if let manifest = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          let helperPath = manifest["path"] as? String
        {
          // Resolve symlinks and validate against trusted prefixes.
          // Execute the resolved path to prevent TOCTOU symlink swaps.
          let resolved = (helperPath as NSString).resolvingSymlinksInPath
          guard trustedPrefixes.contains(where: { resolved.hasPrefix($0) }) else {
            throw TransportError.helperPathUntrusted(resolved)
          }
          return resolved
        }
      }
    }
    throw TransportError.helperNotFound
  }
}

public enum TransportError: LocalizedError {
  case helperNotFound
  case helperCommunicationFailed
  case helperPathUntrusted(String)
  case invalidResponse

  public var errorDescription: String? {
    switch self {
    case .helperNotFound:
      "PasswordManagerBrowserExtensionHelper not found"
    case .helperCommunicationFailed: "Failed to communicate with helper"
    case .helperPathUntrusted(let p):
      "Helper path untrusted: \(p) (must be under /System/ or /Library/)"
    case .invalidResponse: "Invalid response from helper"
    }
  }
}
