import CryptoKit
import XCTest

@testable import Lib

final class AGEStanzaTests: XCTestCase {

  // MARK: - Stanza read/write round-trip

  func testStanza_WriteRead_RoundTrip() throws {
    let original = AGEStanza(
      type: "test-type",
      args: ["arg1", "arg2"],
      body: Data([0x01, 0x02, 0x03, 0x04])
    )
    let stream = MemoryStream()
    try original.writeTo(stream: stream)

    // Feed the output back as input
    let readStream = MemoryStream()
    for line in stream.outputLines {
      readStream.add(input: line)
    }

    let parsed = try AGEStanza.readFrom(stream: readStream)
    XCTAssertEqual(parsed.type, original.type)
    XCTAssertEqual(parsed.args, original.args)
    XCTAssertEqual(parsed.body, original.body)
  }

  func testStanza_WriteRead_EmptyBody() throws {
    let original = AGEStanza(type: "done")
    let stream = MemoryStream()
    try original.writeTo(stream: stream)

    let readStream = MemoryStream()
    for line in stream.outputLines {
      readStream.add(input: line)
    }

    let parsed = try AGEStanza.readFrom(stream: readStream)
    XCTAssertEqual(parsed.type, "done")
    XCTAssertTrue(parsed.args.isEmpty)
    XCTAssertEqual(parsed.body, Data())
  }

  func testStanza_WriteRead_LargeBody() throws {
    // Body larger than 48 bytes requires multi-line encoding
    let body = Data(repeating: 0xAB, count: 100)
    let original = AGEStanza(type: "wrap-file-key", args: ["0"], body: body)
    let stream = MemoryStream()
    try original.writeTo(stream: stream)

    let readStream = MemoryStream()
    for line in stream.outputLines {
      readStream.add(input: line)
    }

    let parsed = try AGEStanza.readFrom(stream: readStream)
    XCTAssertEqual(parsed.body, body)
  }

  func testStanza_ErrorInit() {
    let stanza = AGEStanza(error: "recipient", args: ["0"], message: "invalid key")
    XCTAssertEqual(stanza.type, "error")
    XCTAssertEqual(stanza.args, ["recipient", "0"])
    XCTAssertEqual(stanza.body, Data("invalid key".utf8))
  }

  // MARK: - Stanza parsing errors

  func testStanza_ReadFrom_EmptyStream_Throws() {
    let stream = MemoryStream()
    XCTAssertThrowsError(try AGEStanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as? AGEPlugin.Error, .incompleteStanza)
    }
  }

  func testStanza_ReadFrom_InvalidHeader_Throws() {
    let stream = MemoryStream()
    stream.add(input: "invalid-header")
    stream.add(input: "")
    XCTAssertThrowsError(try AGEStanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as? AGEPlugin.Error, .invalidStanza)
    }
  }

  func testStanza_ReadFrom_MissingArrow_Throws() {
    let stream = MemoryStream()
    stream.add(input: ">> test-type arg1")
    stream.add(input: "")
    XCTAssertThrowsError(try AGEStanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as? AGEPlugin.Error, .invalidStanza)
    }
  }
}

final class AGERecipientTests: XCTestCase {

  // MARK: - Recipient creation via DummyCrypto

  func testAGEIdentity_RoundTrip() throws {
    let crypto = DummyCrypto()
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, &error)!

    let identity = try AGEIdentity(accessControl: accessControl, pq: false, crypto: crypto)
    let encoded = identity.ageIdentity

    // Parse it back
    let decoded = try AGEIdentity(ageIdentity: encoded, crypto: crypto)
    XCTAssertEqual(
      identity.p256PrivateKey.publicKey.compressedRepresentation,
      decoded.p256PrivateKey.publicKey.compressedRepresentation)
  }

  func testAGEIdentity_PQ_RoundTrip() throws {
    let crypto = DummyCrypto()
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, &error)!

    let identity = try AGEIdentity(accessControl: accessControl, pq: true, crypto: crypto)
    let encoded = identity.ageIdentity

    // Parse it back
    let decoded = try AGEIdentity(ageIdentity: encoded, crypto: crypto)
    XCTAssertNotNil(decoded.mlkemPrivateKey)
    XCTAssertEqual(
      identity.p256PrivateKey.publicKey.compressedRepresentation,
      decoded.p256PrivateKey.publicKey.compressedRepresentation)
  }

  func testAGERecipient_Bech32_RoundTrip() throws {
    let crypto = DummyCrypto()
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, &error)!

    let identity = try AGEIdentity(accessControl: accessControl, pq: false, crypto: crypto)
    let recipientStr = identity.recipient.ageRecipient(type: .se)

    // Parse recipient back
    let parsed = try AGERecipient(ageRecipient: recipientStr)
    XCTAssertEqual(
      parsed.p256PublicKey.compressedRepresentation,
      identity.recipient.p256PublicKey.compressedRepresentation)
    XCTAssertNil(parsed.mlkem768PublicKeyRaw)
  }

  func testAGERecipient_Tag_RoundTrip() throws {
    let crypto = DummyCrypto()
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, &error)!

    let identity = try AGEIdentity(accessControl: accessControl, pq: false, crypto: crypto)
    let recipientStr = identity.recipient.ageRecipient(type: .tag)

    let parsed = try AGERecipient(ageRecipient: recipientStr)
    XCTAssertEqual(
      parsed.p256PublicKey.compressedRepresentation,
      identity.recipient.p256PublicKey.compressedRepresentation)
  }

  func testAGERecipient_PQ_RoundTrip() throws {
    let crypto = DummyCrypto()
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, &error)!

    let identity = try AGEIdentity(accessControl: accessControl, pq: true, crypto: crypto)
    let recipientStr = try identity.recipient.ageTagPQRecipient

    let parsed = try AGERecipient(ageRecipient: recipientStr)
    XCTAssertNotNil(parsed.mlkem768PublicKeyRaw)
    XCTAssertEqual(
      parsed.p256PublicKey.x963Representation,
      identity.recipient.p256PublicKey.x963Representation)
  }

  func testAGERecipient_InvalidBech32_Throws() {
    XCTAssertThrowsError(try AGERecipient(ageRecipient: "not-a-valid-recipient"))
  }

  func testAGERecipient_SHA256Tag_Deterministic() throws {
    let crypto = DummyCrypto()
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, &error)!

    let identity = try AGEIdentity(accessControl: accessControl, pq: false, crypto: crypto)
    let tag1 = identity.recipient.sha256Tag
    let tag2 = identity.recipient.sha256Tag
    XCTAssertEqual(tag1, tag2)
    XCTAssertEqual(tag1.count, 4)
  }
}

final class AGEPluginTests: XCTestCase {

  func testGenerateKey_NonPQ() throws {
    let crypto = DummyCrypto()
    let stream = MemoryStream()
    let plugin = AGEPlugin(crypto: crypto, stream: stream)

    let (contents, recipient) = try plugin.generateKey(
      accessControl: .none, recipientType: .se, now: Date(), pq: false)

    XCTAssertTrue(contents.contains("# created:"))
    XCTAssertTrue(contents.contains("# access control: none"))
    XCTAssertTrue(contents.contains("AGE-PLUGIN-SE-"))
    XCTAssertTrue(recipient.hasPrefix("age1se"))
  }

  func testGenerateKey_PQ() throws {
    let crypto = DummyCrypto()
    let stream = MemoryStream()
    let plugin = AGEPlugin(crypto: crypto, stream: stream)

    let (contents, recipient) = try plugin.generateKey(
      accessControl: .none, recipientType: .tag, now: Date(), pq: true)

    XCTAssertTrue(contents.contains("post-quantum"))
    XCTAssertTrue(recipient.hasPrefix("age1tagpq"))
  }

  func testGenerateRecipients() throws {
    let crypto = DummyCrypto()
    let stream = MemoryStream()
    let plugin = AGEPlugin(crypto: crypto, stream: stream)

    // Generate a key first, then extract recipients
    let (contents, _) = try plugin.generateKey(
      accessControl: .none, recipientType: .se, now: Date(), pq: false)

    // Extract the identity line (the one starting with AGE-PLUGIN-SE-)
    let identityLine = contents.split(whereSeparator: \.isNewline)
      .first(where: { $0.hasPrefix("AGE-PLUGIN-SE-") })!
    let recipients = try plugin.generateRecipients(
      input: String(identityLine), recipientType: .se, pq: false)

    XCTAssertTrue(recipients.hasPrefix("age1se"))
  }

  func testGenerateKey_SEUnavailable_Throws() {
    let crypto = DummyCrypto()
    crypto.isSecureEnclaveAvailable = false
    let stream = MemoryStream()
    let plugin = AGEPlugin(crypto: crypto, stream: stream)

    XCTAssertThrowsError(
      try plugin.generateKey(
        accessControl: .none, recipientType: .se, now: Date(), pq: false)
    ) { error in
      XCTAssertEqual(error as? AGEPlugin.Error, .seUnsupported)
    }
  }

  // MARK: - DHKEM encap/decap round-trip

  func testDHKEM_EncapDecap_RoundTrip() throws {
    let crypto = DummyCrypto()

    // Create a recipient key pair
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, &error)!
    let identity = try AGEIdentity(accessControl: accessControl, pq: false, crypto: crypto)

    // Encap
    let (sharedSecret, enc) = try HPKE.dhkemEncap(
      recipientKey: identity.recipient.p256PublicKey, crypto: crypto)

    // Decap
    let decappedSecret = try HPKE.dhkemDecap(enc: enc, recipientKey: identity.p256PrivateKey)

    XCTAssertEqual(
      sharedSecret.withUnsafeBytes { Data($0) },
      decappedSecret.withUnsafeBytes { Data($0) })
  }

  func testHPKE_Context_Deterministic() {
    let key = SymmetricKey(data: Data(repeating: 0xAA, count: 32))
    let info = Data("test-info".utf8)

    let (key1, nonce1) = HPKE.context(kem: .dhkemP256, sharedSecret: key, info: info)
    let (key2, nonce2) = HPKE.context(kem: .dhkemP256, sharedSecret: key, info: info)

    XCTAssertEqual(
      key1.withUnsafeBytes { Data($0) },
      key2.withUnsafeBytes { Data($0) })
    XCTAssertEqual(Data(nonce1), Data(nonce2))
  }
}
