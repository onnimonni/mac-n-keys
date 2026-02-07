import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Manages SSH keys stored in the Secure Enclave via Keychain.
public enum SecureEnclaveKeys {

  public enum KeyAlgorithm: String, Sendable, Codable {
    case ecdsa256
    case mldsa65
    case mldsa87
  }

  public enum AuthRequirement: String, Sendable, Codable {
    case none
    case presence
    case biometry
  }

  public struct KeyInfo: Sendable, Codable {
    public let id: String
    public let name: String
    public let algorithm: KeyAlgorithm
    public let auth: AuthRequirement
  }

  struct StoredAttributes: Codable {
    let algorithm: KeyAlgorithm
    let auth: AuthRequirement
  }

  private static let keyClass = kSecClassGenericPassword as String
  private static let keyTag = Data("build.flaky.mac-n-keys.ssh.key".utf8)

  /// List all stored SSH keys.
  public static func list() -> [(info: KeyInfo, publicKey: Data)] {
    let query = [
      kSecClass: keyClass,
      kSecAttrService: keyTag,
      kSecUseDataProtectionKeychain: true,
      kSecReturnData: true,
      kSecMatchLimit: kSecMatchLimitAll,
      kSecReturnAttributes: true,
    ] as [CFString: Any] as CFDictionary
    var untyped: CFTypeRef?
    unsafe SecItemCopyMatching(query, &untyped)
    guard let typed = untyped as? [[CFString: Any]] else { return [] }
    return typed.compactMap { item in
      guard let name = item[kSecAttrLabel] as? String,
        let id = item[kSecAttrAccount] as? String,
        let attrData = item[kSecAttrGeneric] as? Data,
        let keyData = item[kSecValueData] as? Data,
        let attrs = try? JSONDecoder().decode(StoredAttributes.self, from: attrData)
      else { return nil }
      let publicKey: Data
      do {
        switch attrs.algorithm {
        case .ecdsa256:
          let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData)
          publicKey = key.publicKey.x963Representation
        case .mldsa65:
          let key = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: keyData)
          publicKey = key.publicKey.rawRepresentation
        case .mldsa87:
          let key = try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: keyData)
          publicKey = key.publicKey.rawRepresentation
        }
      } catch { return nil }
      let info = KeyInfo(id: id, name: name, algorithm: attrs.algorithm, auth: attrs.auth)
      return (info: info, publicKey: publicKey)
    }
  }

  /// Create a new SSH key in the Secure Enclave.
  public static func create(
    name: String, algorithm: KeyAlgorithm, auth: AuthRequirement
  ) throws -> (info: KeyInfo, publicKey: Data) {
    let flags: SecAccessControlCreateFlags = switch auth {
    case .none: [.privateKeyUsage]
    case .presence: [.userPresence, .privateKeyUsage]
    case .biometry: [.biometryCurrentSet, .privateKeyUsage]
    }
    let access = try makeAccessControl(flags: flags)

    let dataRep: Data
    let publicKey: Data
    switch algorithm {
    case .ecdsa256:
      let created = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
      dataRep = created.dataRepresentation
      publicKey = created.publicKey.x963Representation
    case .mldsa65:
      let created = try SecureEnclave.MLDSA65.PrivateKey(accessControl: access)
      dataRep = created.dataRepresentation
      publicKey = created.publicKey.rawRepresentation
    case .mldsa87:
      let created = try SecureEnclave.MLDSA87.PrivateKey(accessControl: access)
      dataRep = created.dataRepresentation
      publicKey = created.publicKey.rawRepresentation
    }

    let id = UUID().uuidString
    let attrs = try JSONEncoder().encode(StoredAttributes(algorithm: algorithm, auth: auth))
    let keychainAttrs = [
      kSecClass: keyClass,
      kSecAttrService: keyTag,
      kSecUseDataProtectionKeychain: true,
      kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecAttrAccount: id,
      kSecValueData: dataRep,
      kSecAttrLabel: name,
      kSecAttrGeneric: attrs,
    ] as [CFString: Any] as CFDictionary
    let status = SecItemAdd(keychainAttrs, nil)
    if status != errSecSuccess {
      throw SSHError.keychainError(status)
    }
    let info = KeyInfo(id: id, name: name, algorithm: algorithm, auth: auth)
    return (info: info, publicKey: publicKey)
  }

  /// Sign data with a stored key. Shows Touch ID prompt with caller info.
  public static func sign(keyName: String, data: Data) throws -> Data {
    guard let entry = list().first(where: { $0.info.name == keyName }) else {
      throw SSHError.keyNotFound(keyName)
    }
    let query = [
      kSecClass: keyClass,
      kSecAttrService: keyTag,
      kSecUseDataProtectionKeychain: true,
      kSecAttrAccount: entry.info.id,
      kSecReturnData: true,
      kSecReturnAttributes: true,
    ] as [CFString: Any] as CFDictionary
    var untyped: CFTypeRef?
    let status = unsafe SecItemCopyMatching(query, &untyped)
    if status != errSecSuccess { throw SSHError.keychainError(status) }
    guard let dict = untyped as? [CFString: Any],
      let keyData = dict[kSecValueData] as? Data,
      let attrData = dict[kSecAttrGeneric] as? Data,
      let attrs = try? JSONDecoder().decode(StoredAttributes.self, from: attrData)
    else { throw SSHError.keychainError(errSecSuccess) }

    let context = ProcessTracer.makeAuthContext(
      reason: "Sign SSH request using key \(keyName)")

    switch attrs.algorithm {
    case .ecdsa256:
      let key = try SecureEnclave.P256.Signing.PrivateKey(
        dataRepresentation: keyData, authenticationContext: context)
      return try key.signature(for: data).rawRepresentation
    case .mldsa65:
      let key = try SecureEnclave.MLDSA65.PrivateKey(
        dataRepresentation: keyData, authenticationContext: context)
      return try key.signature(for: data)
    case .mldsa87:
      let key = try SecureEnclave.MLDSA87.PrivateKey(
        dataRepresentation: keyData, authenticationContext: context)
      return try key.signature(for: data)
    }
  }

  /// Delete a stored key. Requires Touch ID unless skipAuth is true.
  public static func delete(keyName: String, skipAuth: Bool = false) throws {
    guard let entry = list().first(where: { $0.info.name == keyName }) else {
      throw SSHError.keyNotFound(keyName)
    }

    var queryDict: [CFString: Any] = [
      kSecClass: keyClass as CFString,
      kSecAttrService: keyTag,
      kSecUseDataProtectionKeychain: true,
      kSecAttrAccount: entry.info.id,
    ]

    if !skipAuth {
      let context = ProcessTracer.makeAuthContext(
        reason: "Delete SSH key '\(keyName)'")
      queryDict[kSecUseAuthenticationContext] = context
    }

    let query = queryDict as CFDictionary
    let status = SecItemDelete(query)
    if status != errSecSuccess { throw SSHError.keychainError(status) }
  }

  /// Get the OpenSSH public key string for a key.
  public static func publicKeyString(keyName: String) throws -> String {
    guard let entry = list().first(where: { $0.info.name == keyName }) else {
      throw SSHError.keyNotFound(keyName)
    }
    let identifier = sshIdentifier(for: entry.info.algorithm)
    let blob = sshPublicKeyBlob(
      algorithm: entry.info.algorithm, publicKey: entry.publicKey)
    let comment = keyName.replacingOccurrences(of: " ", with: "-")
    return "\(identifier) \(blob.base64EncodedString()) \(comment)"
  }

  /// Get SHA256 fingerprint for a key.
  public static func fingerprint(keyName: String) throws -> String {
    guard let entry = list().first(where: { $0.info.name == keyName }) else {
      throw SSHError.keyNotFound(keyName)
    }
    let blob = sshPublicKeyBlob(
      algorithm: entry.info.algorithm, publicKey: entry.publicKey)
    let hash = SHA256.hash(data: blob)
    let base64 = Data(hash).base64EncodedString().replacingOccurrences(of: "=", with: "")
    return "SHA256:\(base64)"
  }

  // MARK: - SSH format helpers

  static func sshIdentifier(for algorithm: KeyAlgorithm) -> String {
    switch algorithm {
    case .ecdsa256: "ecdsa-sha2-nistp256"
    case .mldsa65: "ssh-mldsa-65"
    case .mldsa87: "ssh-mldsa-87"
    }
  }

  static func sshPublicKeyBlob(algorithm: KeyAlgorithm, publicKey: Data) -> Data {
    switch algorithm {
    case .ecdsa256:
      return lengthPrefixed("ecdsa-sha2-nistp256")
        + lengthPrefixed("nistp256")
        + lengthPrefixed(publicKey)
    case .mldsa65:
      return lengthPrefixed("ssh-mldsa-65") + lengthPrefixed(publicKey)
    case .mldsa87:
      return lengthPrefixed("ssh-mldsa-87") + lengthPrefixed(publicKey)
    }
  }

  private static func lengthPrefixed(_ data: Data) -> Data {
    var length = UInt32(data.count).bigEndian
    return unsafe Data(bytes: &length, count: 4) + data
  }

  private static func lengthPrefixed(_ string: String) -> Data {
    lengthPrefixed(Data(string.utf8))
  }
}

public enum SSHError: LocalizedError {
  case keyNotFound(String)
  case keychainError(OSStatus)
  case unsupportedAlgorithm
  case noInputData
  case duplicateKey(String)

  public var errorDescription: String? {
    switch self {
    case .keyNotFound(let n): "Key not found: \(n)"
    case .keychainError(let s): "Keychain error (OSStatus: \(s))"
    case .unsupportedAlgorithm: "Unsupported algorithm on this macOS version"
    case .noInputData: "No input data on stdin"
    case .duplicateKey(let n): "Key '\(n)' already exists"
    }
  }
}
