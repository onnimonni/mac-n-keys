import CryptoKit
import Foundation
import LocalAuthentication

/// Abstraction for random/unpredictable/system-specific crypto operations
public protocol AGECrypto {
  var isSecureEnclaveAvailable: Bool { get }

  func newSecureEnclaveP256PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveP256PrivateKey
  func newSecureEnclaveP256PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveP256PrivateKey
  func newEphemeralP256PrivateKey() -> P256.KeyAgreement.PrivateKey

  func newSecureEnclaveMLKEM768PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveMLKEM768PrivateKey
  func newSecureEnclaveMLKEM768PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveMLKEM768PrivateKey
  func encapsulate(mlkem768KeyRaw: Data) throws -> (sharedSecret: Data, encapsulated: Data)
}

public protocol SecureEnclaveP256PrivateKey {
  var publicKey: P256.KeyAgreement.PublicKey { get }
  var dataRepresentation: Data { get }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> SharedSecret
}

public protocol SecureEnclaveMLKEM768PrivateKey {
  var publicKeyRawRepresentation: Data { get }
  var dataRepresentation: Data { get }

  func decapsulate(_ encapsulated: Data) throws -> SymmetricKey
}

/// CryptoKit-backed implementation with fresh LAContext per operation for observability.
public struct CryptoKitCrypto: AGECrypto {

  public init() {}

  /// Create a fresh LAContext with caller info in the Touch ID prompt.
  private func makeContext() -> LAContext {
    ProcessTracer.makeAuthContext(reason: "Decrypting")
  }

  public var isSecureEnclaveAvailable: Bool {
    SecureEnclave.isAvailable
  }

  public func newSecureEnclaveP256PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveP256PrivateKey
  {
    let context = makeContext()
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: dataRepresentation, authenticationContext: context)
  }

  public func newSecureEnclaveP256PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveP256PrivateKey
  {
    let context = makeContext()
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(
      accessControl: accessControl, authenticationContext: context)
  }

  public func newEphemeralP256PrivateKey() -> P256.KeyAgreement.PrivateKey {
    P256.KeyAgreement.PrivateKey()
  }

  public func newSecureEnclaveMLKEM768PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveMLKEM768PrivateKey
  {
    let context = makeContext()
    return MLKEM768PrivateKeyWrapper(
      try SecureEnclave.MLKEM768.PrivateKey(
        dataRepresentation: dataRepresentation, authenticationContext: context))
  }

  public func newSecureEnclaveMLKEM768PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveMLKEM768PrivateKey
  {
    let context = makeContext()
    return MLKEM768PrivateKeyWrapper(
      try SecureEnclave.MLKEM768.PrivateKey(
        accessControl: accessControl, authenticationContext: context))
  }

  public func encapsulate(mlkem768KeyRaw: Data) throws -> (
    sharedSecret: Data, encapsulated: Data
  ) {
    let publicKey = try MLKEM768.PublicKey(rawRepresentation: mlkem768KeyRaw)
    let result = try publicKey.encapsulate()
    return (
      sharedSecret: result.sharedSecret.withUnsafeBytes { Data($0) },
      encapsulated: result.encapsulated
    )
  }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecureEnclaveP256PrivateKey {
}

struct MLKEM768PrivateKeyWrapper: SecureEnclaveMLKEM768PrivateKey {
  let key: SecureEnclave.MLKEM768.PrivateKey

  init(_ key: SecureEnclave.MLKEM768.PrivateKey) {
    self.key = key
  }

  var publicKeyRawRepresentation: Data {
    key.publicKey.rawRepresentation
  }

  var dataRepresentation: Data {
    key.dataRepresentation
  }

  func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
    try key.decapsulate(encapsulated)
  }
}
