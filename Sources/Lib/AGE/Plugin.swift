import CryptoKit
import Foundation

public class AGEPlugin {
  public let crypto: AGECrypto
  public let stream: AGEStream

  public init(crypto: AGECrypto, stream: AGEStream) {
    self.crypto = crypto
    self.stream = stream
  }

  public func generateKey(
    accessControl: AGEKeyAccessControl, recipientType: AGERecipientType, now: Date,
    pq: Bool = false
  ) throws -> (String, String) {
    if !crypto.isSecureEnclaveAvailable {
      throw Error.seUnsupported
    }
    let createdAt = now.ISO8601Format()
    #if !os(Linux) && !os(Windows)
      var accessControlFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
      if accessControl == .anyBiometry || accessControl == .anyBiometryAndPasscode {
        accessControlFlags.insert(.biometryAny)
      }
      if accessControl == .currentBiometry || accessControl == .currentBiometryAndPasscode {
        accessControlFlags.insert(.biometryCurrentSet)
      }
      if accessControl == .passcode || accessControl == .anyBiometryAndPasscode
        || accessControl == .currentBiometryAndPasscode
      {
        accessControlFlags.insert(.devicePasscode)
      }
      if accessControl == .anyBiometryOrPasscode {
        accessControlFlags.insert(.userPresence)
      }
      let secAccessControl = try makeAccessControl(flags: accessControlFlags)
    #else
      let secAccessControl = SecAccessControl()
    #endif

    let identity = try AGEIdentity(
      accessControl: secAccessControl, pq: pq, crypto: self.crypto)
    let accessControlStr = accessControl.rawValue

    let ageRecipient: String
    var recipientsStr = "# public key: \(identity.recipient.ageRecipient(type: recipientType))"
    if pq {
      ageRecipient = try identity.recipient.ageTagPQRecipient
      recipientsStr += "\n# public key (post-quantum): \(ageRecipient)"
    } else {
      ageRecipient = identity.recipient.ageRecipient(type: recipientType)
    }

    let contents = """
      # created: \(createdAt)
      # access control: \(accessControlStr)
      \(recipientsStr)
      \(identity.ageIdentity)

      """

    return (contents, ageRecipient)
  }

  public func generateRecipients(input: String, recipientType: AGERecipientType, pq: Bool = false)
    throws
    -> String
  {
    var recipients: [String] = []
    for l in input.split(whereSeparator: \.isNewline) {
      if l.hasPrefix("#") {
        continue
      }
      let sl = String(l.trimmingCharacters(in: .whitespacesAndNewlines))
      let identity = try AGEIdentity(ageIdentity: sl, crypto: self.crypto)
      if pq {
        recipients.append(try identity.recipient.ageTagPQRecipient)
      } else {
        recipients.append(identity.recipient.ageRecipient(type: recipientType))
      }
    }
    return recipients.joined(separator: "\n")
  }

  public func runRecipientV1() throws {
    var recipients: [String] = []
    var identities: [String] = []
    var fileKeys: [Data] = []

    // Phase 1
    loop: while true {
      let stanza = try AGEStanza.readFrom(stream: stream)
      switch stanza.type {
      case "add-recipient":
        recipients.append(stanza.args[0])
      case "add-identity":
        identities.append(stanza.args[0])
      case "wrap-file-key":
        fileKeys.append(stanza.body)
      case "done":
        break loop
      default:
        continue
      }
    }

    // Phase 2
    var stanzas: [AGEStanza] = []
    var errors: [AGEStanza] = []
    var recipientKeys: [(AGERecipient, AGERecipientStanzaType)] = []
    for (index, recipient) in recipients.enumerated() {
      do {
        recipientKeys.append(
          (
            try AGERecipient(ageRecipient: recipient),
            recipient.starts(with: "age1tag1")
              ? .p256tag
              : recipient.starts(with: "age1tagpq") ? .mlkem768p256tag : .pivp256
          ))
      } catch {
        errors.append(
          AGEStanza(
            error: "recipient", args: [String(index)],
            message: error.localizedDescription))
      }
    }
    for (index, identity) in identities.enumerated() {
      do {
        recipientKeys.append(
          (
            (try AGEIdentity(ageIdentity: identity, crypto: crypto)).recipient,
            .pivp256
          ))
      } catch {
        errors.append(
          AGEStanza(
            error: "identity", args: [String(index)],
            message: error.localizedDescription))
      }
    }
    for (index, fileKey) in fileKeys.enumerated() {
      for (recipientKey, recipientStanzaType) in recipientKeys {
        do {
          var tag: Data
          var nonce: ChaChaPoly.Nonce
          var wrapKey: SymmetricKey
          var pkEBytes: Data

          switch recipientStanzaType {
          case .pivp256:
            let skE = self.crypto.newEphemeralP256PrivateKey()
            pkEBytes = skE.publicKey.compressedRepresentation
            tag = recipientKey.sha256Tag
            nonce = try ChaChaPoly.Nonce(data: Data(count: 12))

            let sharedSecret = try skE.sharedSecretFromKeyAgreement(
              with: recipientKey.p256PublicKey)
            wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
              using: SHA256.self,
              salt: pkEBytes + recipientKey.p256PublicKey.compressedRepresentation,
              sharedInfo: Data("piv-p256".utf8),
              outputByteCount: 32
            )

          case .p256tag:
            let (sharedSecret, enc) = try HPKE.dhkemEncap(
              recipientKey: recipientKey.p256PublicKey, crypto: crypto)
            (wrapKey, nonce) = HPKE.context(
              kem: recipientStanzaType.kem!,
              sharedSecret: sharedSecret,
              info: recipientStanzaType.hpkeInfo!)
            tag = recipientKey.p256HKDFTag(using: enc)
            pkEBytes = enc

          case .mlkem768p256tag:
            guard let mlkemRaw = recipientKey.mlkem768PublicKeyRaw else {
              throw Error.missingPQ
            }
            let (sharedSecret, enc) = try HPKE.mlkemp256Encap(
              recipientP256Key: recipientKey.p256PublicKey,
              recipientMLKEM768KeyRaw: mlkemRaw,
              crypto: crypto)
            (wrapKey, nonce) = HPKE.context(
              kem: recipientStanzaType.kem!,
              sharedSecret: sharedSecret,
              info: recipientStanzaType.hpkeInfo!)
            tag = recipientKey.mlkem768p256HKDFTag(using: enc)
            pkEBytes = enc
          }

          let sealedBox = try ChaChaPoly.seal(fileKey, using: wrapKey, nonce: nonce)
          stanzas.append(
            AGEStanza(
              type: "recipient-stanza",
              args: [
                String(index),
                recipientStanzaType.rawValue,
                tag.base64RawEncodedString(),
                pkEBytes.base64RawEncodedString(),
              ], body: sealedBox.ciphertext + sealedBox.tag
            )
          )
        } catch {
          errors.append(
            AGEStanza(error: "internal", args: [], message: error.localizedDescription))
        }
      }
    }
    for stanza in (errors.isEmpty ? stanzas : errors) {
      try stanza.writeTo(stream: stream)
      let resp = try AGEStanza.readFrom(stream: stream)
      assert(resp.type == "ok")
    }
    try AGEStanza(type: "done").writeTo(stream: stream)
  }

  public func runIdentityV1() throws {
    // Phase 1
    var identities: [String] = []
    var recipientStanzas: [AGEStanza] = []
    loop: while true {
      let stanza = try AGEStanza.readFrom(stream: stream)
      switch stanza.type {
      case "add-identity":
        identities.append(stanza.args[0])
      case "recipient-stanza":
        recipientStanzas.append(stanza)
      case "done":
        break loop
      default:
        continue
      }
    }

    // Phase 2
    var identityKeys: [AGEIdentity] = []
    var errors: [AGEStanza] = []

    for (index, identity) in identities.enumerated() {
      do {
        identityKeys.append(
          (try AGEIdentity(ageIdentity: identity, crypto: crypto)))
      } catch {
        errors.append(
          AGEStanza(
            error: "identity", args: [String(index)],
            message: error.localizedDescription))
      }
    }

    var fileResponses: [Int: AGEStanza] = [:]
    if errors.isEmpty {
      // Check structural validity
      for recipientStanza in recipientStanzas {
        guard let fileIndex = Int(recipientStanza.args[0]) else {
          continue
        }
        guard let stanzaType = AGERecipientStanzaType(rawValue: recipientStanza.args[1]) else {
          continue
        }
        if recipientStanza.args.count != 4 {
          fileResponses[fileIndex] = AGEStanza(
            error: "stanza", args: [String(fileIndex)],
            message: "incorrect argument count")
          continue
        }
        guard let tag = Data(base64RawEncoded: recipientStanza.args[2]), tag.count == 4 else {
          fileResponses[fileIndex] = AGEStanza(
            error: "stanza", args: [String(fileIndex)], message: "invalid tag")
          continue
        }
        guard let share = Data(base64RawEncoded: recipientStanza.args[3]),
          share.count == stanzaType.expectedShareSize
        else {
          fileResponses[fileIndex] = AGEStanza(
            error: "stanza", args: [String(fileIndex)], message: "invalid share")
          continue
        }
        if recipientStanza.body.count != 32 {
          fileResponses[fileIndex] = AGEStanza(
            error: "stanza", args: [String(fileIndex)],
            message: "invalid body")
          continue
        }
      }

      // Unwrap keys
      for recipientStanza in recipientStanzas {
        guard let fileIndex = Int(recipientStanza.args[0]) else {
          continue
        }
        if fileResponses[fileIndex] != nil {
          continue
        }
        guard let type = AGERecipientStanzaType(rawValue: recipientStanza.args[1]) else {
          continue
        }
        let tag = recipientStanza.args[2]
        let share = recipientStanza.args[3]
        for identity in identityKeys {
          do {
            let shareKeyData = Data(base64RawEncoded: share)!
            let identityTag =
              (type == .p256tag
              ? identity.recipient.p256HKDFTag(using: shareKeyData)
              : type == .mlkem768p256tag
                ? identity.recipient.mlkem768p256HKDFTag(using: shareKeyData)
                : identity.recipient.sha256Tag)
              .base64RawEncodedString()
            if identityTag != tag {
              continue
            }

            var nonce: ChaChaPoly.Nonce
            var wrapKey: SymmetricKey

            switch type {
            case .pivp256:
              let shareKey = try P256.KeyAgreement.PublicKey(
                compressedRepresentation: shareKeyData)
              let sharedSecret = try identity.p256PrivateKey
                .sharedSecretFromKeyAgreement(
                  with: shareKey)
              wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: shareKeyData
                  + identity.recipient.p256PublicKey.compressedRepresentation,
                sharedInfo: Data("piv-p256".utf8),
                outputByteCount: 32
              )
              nonce = try ChaChaPoly.Nonce(data: Data(count: 12))

            case .p256tag:
              let sharedSecret = try HPKE.dhkemDecap(
                enc: shareKeyData, recipientKey: identity.p256PrivateKey)
              (wrapKey, nonce) = HPKE.context(
                kem: type.kem!, sharedSecret: sharedSecret, info: type.hpkeInfo!)

            case .mlkem768p256tag:
              guard let mlkemKey = identity.mlkemPrivateKey else {
                throw Error.missingPQ
              }
              let sharedSecret = try HPKE.mlkemp256Decap(
                enc: shareKeyData,
                recipientP256Key: identity.p256PrivateKey,
                recipientMLKEM768Key: mlkemKey)
              (wrapKey, nonce) = HPKE.context(
                kem: type.kem!, sharedSecret: sharedSecret, info: type.hpkeInfo!)
            }

            let unwrappedKey = try ChaChaPoly.open(
              ChaChaPoly.SealedBox(combined: nonce + recipientStanza.body),
              using: wrapKey)
            fileResponses[fileIndex] = AGEStanza(
              type: "file-key",
              args: [String(fileIndex)],
              body: unwrappedKey
            )
          } catch {
            try AGEStanza(type: "msg", body: Data(error.localizedDescription.utf8)).writeTo(
              stream: stream)
            let resp = try AGEStanza.readFrom(stream: self.stream)
            assert(resp.type == "ok")
          }
        }
      }
    }

    let responses = fileResponses.keys.sorted().compactMap({ fileResponses[$0] })
    for stanza in (errors.isEmpty ? responses : errors) {
      try stanza.writeTo(stream: stream)
      let resp = try AGEStanza.readFrom(stream: stream)
      assert(resp.type == "ok")
    }
    try AGEStanza(type: "done").writeTo(stream: stream)
  }

  public enum Error: LocalizedError, Equatable {
    case seUnsupported
    case pqUnsupported
    case pqUnavailable
    case incompleteStanza
    case invalidStanza
    case invalidRecipient
    case unknownHRP(String)
    case missingPQ
    case corruptedIdentity

    public var errorDescription: String? {
      switch self {
      case .seUnsupported: return "Secure Enclave not supported on this device"
      case .pqUnsupported: return "Post-quantum not supported in this build"
      case .pqUnavailable: return "This OS does not support post-quantum"
      case .incompleteStanza: return "incomplete stanza"
      case .invalidStanza: return "invalid stanza"
      case .invalidRecipient: return "invalid recipient"
      case .unknownHRP(let hrp): return "unknown HRP: \(hrp)"
      case .missingPQ: return "missing post-quantum key support"
      case .corruptedIdentity: return "corrupted hybrid identity data"
      }
    }
  }
}

//////////////////////////////////////////////////////////////////////////////////////////

public struct AGEStanza: Equatable {
  public var type: String
  public var args: [String] = []
  public var body = Data()

  public init(type: String, args: [String] = [], body: Data = Data()) {
    self.type = type
    self.args = args
    self.body = body
  }

  public static func readFrom(stream: AGEStream) throws -> AGEStanza {
    guard let header = try stream.readLine() else {
      throw AGEPlugin.Error.incompleteStanza
    }
    let headerParts = header.components(separatedBy: " ")
    if headerParts.count < 2 {
      throw AGEPlugin.Error.invalidStanza
    }
    if headerParts[0] != "->" {
      throw AGEPlugin.Error.invalidStanza
    }
    var body = Data()
    while true {
      guard let line = try stream.readLine() else {
        throw AGEPlugin.Error.incompleteStanza
      }
      guard let lineData = Data(base64RawEncoded: line) else {
        throw AGEPlugin.Error.invalidStanza
      }
      if lineData.count > 48 {
        throw AGEPlugin.Error.invalidStanza
      }
      body.append(lineData)
      if lineData.count < 48 {
        break
      }
    }
    return AGEStanza(type: headerParts[1], args: Array(headerParts[2...]), body: body)
  }

  public func writeTo(stream: AGEStream) throws {
    let parts = ([type] + args).joined(separator: " ")
    try stream.writeLine("-> \(parts)\n\(body.base64RawEncodedString(wrap: true))")
  }
}

extension AGEStanza {
  public init(error type: String, args: [String] = [], message: String) {
    self.type = "error"
    self.args = [type] + args
    self.body = Data(message.utf8)
  }
}

public enum AGEKeyAccessControl: String {
  case none = "none"
  case passcode = "passcode"
  case anyBiometry = "any-biometry"
  case anyBiometryOrPasscode = "any-biometry-or-passcode"
  case anyBiometryAndPasscode = "any-biometry-and-passcode"
  case currentBiometry = "current-biometry"
  case currentBiometryAndPasscode = "current-biometry-and-passcode"
}

public enum AGERecipientType: String {
  case se = "se"
  case tag = "tag"
}

public enum AGERecipientStanzaType: String {
  case p256tag = "p256tag"
  case mlkem768p256tag = "mlkem768p256tag"
  case pivp256 = "piv-p256"

  /// Expected share (ephemeral public key) size for structural validation.
  public var expectedShareSize: Int {
    switch self {
    case .pivp256: 33
    case .p256tag: 65
    case .mlkem768p256tag: 1153
    }
  }

  /// HKDF info string for HPKE context derivation.
  public var hpkeInfo: Data? {
    switch self {
    case .pivp256: nil
    case .p256tag: Data("age-encryption.org/p256tag".utf8)
    case .mlkem768p256tag: Data("age-encryption.org/mlkem768p256tag".utf8)
    }
  }

  /// HPKE KEM type for context derivation.
  public var kem: HPKE.KEM? {
    switch self {
    case .pivp256: nil
    case .p256tag: .dhkemP256
    case .mlkem768p256tag: .mlkem768P256
    }
  }
}

////////////////////////////////////////////////////////////////////////////////

public struct AGERecipient {
  public let p256PublicKey: P256.KeyAgreement.PublicKey
  /// Raw representation of MLKEM768 public key (stored as Data to avoid availability issues)
  public let mlkem768PublicKeyRaw: Data?

  public init(ageRecipient: String) throws {
    let id = try Bech32.decode(ageRecipient)
    switch id.hrp {
    case "age1se", "age1tag":
      if id.data.count != 33 {
        throw AGEPlugin.Error.invalidRecipient
      }
      self.p256PublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: id.data)
      self.mlkem768PublicKeyRaw = nil
    case "age1tagpq":
      if id.data.count != 1184 + 65 {
        throw AGEPlugin.Error.invalidRecipient
      }
      self.p256PublicKey = try P256.KeyAgreement.PublicKey(
        x963Representation: id.data[1184...])
      self.mlkem768PublicKeyRaw = Data(id.data[..<1184])
    default:
      throw AGEPlugin.Error.unknownHRP(id.hrp)
    }
  }

  public init(
    p256PublicKey: P256.KeyAgreement.PublicKey, mlkem768PublicKeyRaw: Data? = nil
  ) {
    self.p256PublicKey = p256PublicKey
    self.mlkem768PublicKeyRaw = mlkem768PublicKeyRaw
  }

  public var sha256Tag: Data {
    return Data(SHA256.hash(data: self.p256PublicKey.compressedRepresentation).prefix(4))
  }

  public func p256HKDFTag(using: Data) -> Data {
    return Data(
      HKDF<SHA256>.extract(
        inputKeyMaterial: SymmetricKey(data: using + self.sha256Tag),
        salt: Data("age-encryption.org/p256tag".utf8))
    ).prefix(4)
  }

  public func mlkem768p256HKDFTag(using: Data) -> Data {
    let recipientHash = Data(SHA256.hash(data: self.p256PublicKey.x963Representation).prefix(4))
    return Data(
      HKDF<SHA256>.extract(
        inputKeyMaterial: SymmetricKey(data: using + recipientHash.prefix(4)),
        salt: Data("age-encryption.org/mlkem768p256tag".utf8))
    ).prefix(4)
  }

  public func ageRecipient(type: AGERecipientType) -> String {
    return Bech32.encode(
      hrp: "age1\(type.rawValue)", data: self.p256PublicKey.compressedRepresentation)
  }

  public var ageTagPQRecipient: String {
    get throws {
      guard let mlkem768Raw = self.mlkem768PublicKeyRaw else {
        throw AGEPlugin.Error.missingPQ
      }
      return Bech32.encode(
        hrp: "age1tagpq",
        data: mlkem768Raw + self.p256PublicKey.x963Representation)
    }
  }
}

public struct AGEIdentity {
  public let p256PrivateKey: SecureEnclaveP256PrivateKey
  public let mlkemPrivateKey: SecureEnclaveMLKEM768PrivateKey?

  public init(ageIdentity: String, crypto: AGECrypto) throws {
    let id = try Bech32.decode(ageIdentity)
    if id.hrp != "AGE-PLUGIN-SE-" {
      throw AGEPlugin.Error.unknownHRP(id.hrp)
    }
    let parsed = try AGEIdentity.parseData(id.data)
    if parsed.isHybridFormat {
      guard let mlkemData = parsed.mlkemData else {
        throw AGEPlugin.Error.corruptedIdentity
      }
      self.p256PrivateKey = try crypto.newSecureEnclaveP256PrivateKey(
        dataRepresentation: parsed.p256Data)
      self.mlkemPrivateKey = try crypto.newSecureEnclaveMLKEM768PrivateKey(
        dataRepresentation: mlkemData)
    } else {
      self.p256PrivateKey = try crypto.newSecureEnclaveP256PrivateKey(
        dataRepresentation: parsed.p256Data)
      self.mlkemPrivateKey = nil
    }
  }

  public init(accessControl: SecAccessControl, pq: Bool, crypto: AGECrypto) throws {
    self.p256PrivateKey = try crypto.newSecureEnclaveP256PrivateKey(
      accessControl: accessControl)
    if pq {
      self.mlkemPrivateKey = try crypto.newSecureEnclaveMLKEM768PrivateKey(
        accessControl: accessControl)
    } else {
      self.mlkemPrivateKey = nil
    }
  }

  private static func parseData(_ data: Data) throws -> (
    p256Data: Data, mlkemData: Data?, isHybridFormat: Bool
  ) {
    // Too short for a length prefix → legacy P-256 only
    guard data.count >= 2 else {
      return (data, nil, false)
    }

    let p256Count = Int(data[0]) << 8 | Int(data[1])

    // Sanity: if the encoded p256 length is 0 or would consume all data
    // (leaving no room for the MLKEM length prefix), treat as legacy P-256
    guard p256Count > 0, p256Count + 2 < data.count else {
      return (data, nil, false)
    }

    // Valid-looking length prefix → this is hybrid format
    var offset = 2
    guard data.count >= offset + p256Count else {
      throw AGEPlugin.Error.corruptedIdentity
    }
    let p256Data = data[offset..<(offset + p256Count)]
    offset += p256Count

    // MLKEM length prefix
    guard data.count >= offset + 2 else {
      throw AGEPlugin.Error.corruptedIdentity
    }
    let mlkemCount = Int(data[offset]) << 8 | Int(data[offset + 1])
    offset += 2
    guard data.count >= offset + mlkemCount, mlkemCount > 0 else {
      throw AGEPlugin.Error.corruptedIdentity
    }
    let mlkemData = data[offset..<(offset + mlkemCount)]
    offset += mlkemCount

    // No trailing bytes allowed
    guard data.count == offset else {
      throw AGEPlugin.Error.corruptedIdentity
    }
    return (p256Data: Data(p256Data), mlkemData: Data(mlkemData), true)
  }

  public var recipient: AGERecipient {
    return AGERecipient(
      p256PublicKey: self.p256PrivateKey.publicKey,
      mlkem768PublicKeyRaw: self.mlkemPrivateKey?.publicKeyRawRepresentation)
  }

  public var ageIdentity: String {
    var data: Data
    if self.mlkemPrivateKey == nil {
      data = self.p256PrivateKey.dataRepresentation
    } else {
      let p256data = self.p256PrivateKey.dataRepresentation
      let mlkemdata = self.mlkemPrivateKey!.dataRepresentation
      data =
        Data([UInt8(p256data.count >> 8), UInt8(p256data.count & 0xFF)]) + p256data
        + Data([UInt8(mlkemdata.count >> 8), UInt8(mlkemdata.count & 0xFF)]) + mlkemdata
    }
    return Bech32.encode(hrp: "AGE-PLUGIN-SE-", data: data)
  }
}
