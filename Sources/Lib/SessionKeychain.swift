import Foundation
import LocalAuthentication
import Security

/// Stores SRP session keys in macOS Keychain with Touch ID protection.
public enum SessionKeychain {

  private static let service = "build.flaky.mac-n-keys.passwords.session"
  private static let metadataAccount = "session-metadata"

  /// Session validity duration (24 hours).
  private static let maxSessionAge: TimeInterval = 24 * 60 * 60

  private struct SessionMetadata: Codable {
    let createdAt: Date
  }

  /// Save session data to Keychain with SecAccessControl (.userPresence).
  public static func save(username: String, sharedKey: Data, socketPath: String) throws {
    // Delete any existing session first
    try? delete()

    let now = Date()
    let sessionData = try JSONEncoder().encode(
      SessionData(
        username: username, sharedKey: sharedKey, socketPath: socketPath,
        createdAt: now))

    // Require Touch ID / passcode for access
    let access = try makeAccessControl(flags: .userPresence)

    let query = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: "session",
      kSecValueData: sessionData,
      kSecAttrAccessControl: access as Any,
    ] as [CFString: Any] as CFDictionary

    let status = SecItemAdd(query, nil)
    if status != errSecSuccess {
      throw SessionKeychainError.saveFailed(status)
    }

    // Save plaintext metadata (no auth required) for pre-auth expiry check
    let metadataData = try JSONEncoder().encode(SessionMetadata(createdAt: now))
    let metaQuery = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: metadataAccount,
      kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecValueData: metadataData,
    ] as [CFString: Any] as CFDictionary
    SecItemAdd(metaQuery, nil)
  }

  /// Load session data from Keychain. Triggers Touch ID with caller info.
  /// Checks expiry via plaintext metadata BEFORE triggering Touch ID.
  public static func load(forDomain domain: String? = nil) throws -> SessionData {
    // Check expiry from plaintext metadata first (no Touch ID needed)
    let metaQuery = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: metadataAccount,
      kSecReturnData: true,
    ] as [CFString: Any] as CFDictionary

    var metaResult: CFTypeRef?
    let metaStatus = SecItemCopyMatching(metaQuery, &metaResult)
    if metaStatus == errSecSuccess, let metaData = metaResult as? Data,
      let metadata = try? JSONDecoder().decode(SessionMetadata.self, from: metaData)
    {
      if Date().timeIntervalSince(metadata.createdAt) > maxSessionAge {
        try? delete()
        throw SessionKeychainError.sessionExpired
      }
    } else if metaStatus == errSecItemNotFound {
      throw SessionKeychainError.loadFailed(errSecItemNotFound)
    }

    // Metadata valid — proceed with authenticated query (Touch ID)
    let reason = domain.map { "Accessing password for \($0)" } ?? "Accessing passwords"
    let context = ProcessTracer.makeAuthContext(reason: reason)

    let query = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: "session",
      kSecReturnData: true,
      kSecUseAuthenticationContext: context,
    ] as [CFString: Any] as CFDictionary

    var result: CFTypeRef?
    let status = unsafe SecItemCopyMatching(query, &result)
    if status != errSecSuccess {
      throw SessionKeychainError.loadFailed(status)
    }
    guard let data = result as? Data else {
      throw SessionKeychainError.loadFailed(errSecSuccess)
    }
    let session = try JSONDecoder().decode(SessionData.self, from: data)

    // Double-check session age (belt and suspenders — metadata could be tampered)
    if Date().timeIntervalSince(session.createdAt) > maxSessionAge {
      try? delete()
      throw SessionKeychainError.sessionExpired
    }

    return session
  }

  /// Delete stored session and metadata.
  public static func delete() throws {
    let query = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: "session",
    ] as [CFString: Any] as CFDictionary

    let status = SecItemDelete(query)
    if status != errSecSuccess && status != errSecItemNotFound {
      throw SessionKeychainError.deleteFailed(status)
    }

    // Also delete plaintext metadata
    let metaQuery = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: metadataAccount,
    ] as [CFString: Any] as CFDictionary
    SecItemDelete(metaQuery)
  }

  public struct SessionData: Codable, Sendable {
    public let username: String
    public let sharedKey: Data
    public let socketPath: String
    public let createdAt: Date
  }
}

public enum SessionKeychainError: LocalizedError {
  case saveFailed(OSStatus)
  case loadFailed(OSStatus)
  case deleteFailed(OSStatus)
  case sessionExpired

  public var errorDescription: String? {
    switch self {
    case .saveFailed(let s): "Failed to save session (OSStatus: \(s))"
    case .loadFailed(let s): "Failed to load session (OSStatus: \(s))"
    case .deleteFailed(let s): "Failed to delete session (OSStatus: \(s))"
    case .sessionExpired: "Session expired. Please re-authenticate with 'passwords auth'"
    }
  }
}
