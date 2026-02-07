import BigInt
import XCTest

@testable import Lib

final class SRPTests: XCTestCase {
  func testSessionCreation() throws {
    let session = try SRPSession.create()
    XCTAssertFalse(session.username.isEmpty)
    XCTAssertGreaterThan(session.clientPublicKey, BigUInt(0))
  }

  func testClientPublicKey_IsConsistent() throws {
    let session = try SRPSession.create()
    let a = session.clientPublicKey
    let b = session.clientPublicKey
    XCTAssertEqual(a, b)
  }

  func testSerializeDeserialize_Hex() throws {
    let session = try SRPSession.create(useBase64: false)
    let data = Data([0x01, 0x02, 0x03, 0xAB, 0xCD])
    let serialized = session.serialize(data)
    XCTAssertTrue(serialized.hasPrefix("0x"))
    let deserialized = session.deserialize(serialized)
    XCTAssertEqual(data, deserialized)
  }

  func testSerializeDeserialize_Base64() throws {
    let session = try SRPSession.create(useBase64: true)
    let data = Data([0x01, 0x02, 0x03, 0xAB, 0xCD])
    let serialized = session.serialize(data)
    XCTAssertFalse(serialized.hasPrefix("0x"))
    let deserialized = session.deserialize(serialized)
    XCTAssertEqual(data, deserialized)
  }

  func testSetServerPublicKey_RejectsZero() throws {
    let session = try SRPSession.create()
    XCTAssertThrowsError(
      try session.setServerPublicKey(BigUInt(0), salt: BigUInt(1234))
    )
  }

  func testSRPConstants() {
    XCTAssertEqual(SRPConstants.groupGenerator, 5)
    XCTAssertEqual(SRPConstants.groupPrimeBytes, 384)
    XCTAssertGreaterThan(SRPConstants.groupPrime, BigUInt(0))
  }

  // MARK: - Bug fix regression tests

  /// C2: restore() must preserve the username string exactly.
  /// Previously, restore() passed Data() to init which computed an empty username,
  /// breaking TID checks on subsequent encrypt/decrypt operations.
  func testRestore_PreservesUsername() throws {
    let original = try SRPSession.create(useBase64: true)
    let originalUsername = original.username
    XCTAssertFalse(originalUsername.isEmpty)

    let restored = SRPSession.restore(
      username: originalUsername, sharedKey: BigUInt(42), useBase64: true)
    XCTAssertEqual(restored.username, originalUsername,
      "Restored session must have the exact same username")
  }

  func testRestore_PreservesUsername_Hex() throws {
    let original = try SRPSession.create(useBase64: false)
    let originalUsername = original.username
    XCTAssertTrue(originalUsername.hasPrefix("0x"))

    let restored = SRPSession.restore(
      username: originalUsername, sharedKey: BigUInt(42), useBase64: false)
    XCTAssertEqual(restored.username, originalUsername)
  }

  /// C1: Encrypt/decrypt round-trip with intentionally asymmetric wire formats.
  /// Client→server: ciphertext + tag + iv (iv at end)
  /// Server→client: iv + ciphertext + tag (iv at start)
  func testEncryptDecrypt_RoundTrip() throws {
    let session = try SRPSession.create(useBase64: true)
    // Set up a shared key by simulating the handshake internals
    let restoredSession = SRPSession.restore(
      username: session.username, sharedKey: BigUInt(Data(repeating: 0xAB, count: 32)),
      useBase64: true)

    let plaintext = Data("hello world".utf8)
    let encrypted = try restoredSession.encrypt(plaintext)

    // Verify encrypted data structure: ciphertext + tag(16) + iv(12)
    // Minimum size: plaintext + 16 (tag) + 12 (iv) = 11 + 28 = 39
    XCTAssertGreaterThanOrEqual(encrypted.count, plaintext.count + 28)

    // To test decrypt, we need to reformat from client→server to server→client format:
    // encrypted = ciphertext + tag(16) + iv(12)  (client→server)
    // decrypt expects: iv(12) + ciphertext + tag(16) (server→client)
    let iv = encrypted.suffix(12)
    let ciphertextAndTag = encrypted.dropLast(12)
    let serverFormat = iv + ciphertextAndTag

    let decrypted = try restoredSession.decrypt(serverFormat)
    XCTAssertEqual(decrypted, plaintext)
  }

  /// Encrypt without a shared key should throw.
  func testEncrypt_WithoutSharedKey_Throws() throws {
    let session = try SRPSession.create()
    XCTAssertThrowsError(try session.encrypt(Data("test".utf8)))
  }

  /// Decrypt without a shared key should throw.
  func testDecrypt_WithoutSharedKey_Throws() throws {
    let session = try SRPSession.create()
    XCTAssertThrowsError(try session.decrypt(Data(repeating: 0, count: 48)))
  }

  /// bigUIntToData serialization round-trip.
  func testBigUIntToData_RoundTrip() throws {
    let session = try SRPSession.create()
    let value = BigUInt(123456789)
    let data = session.bigUIntToData(value)
    let restored = BigUInt(data)
    XCTAssertEqual(value, restored)
  }

  func testBigUIntToData_Zero() throws {
    let session = try SRPSession.create()
    let data = session.bigUIntToData(BigUInt(0))
    XCTAssertEqual(BigUInt(data), BigUInt(0))
  }

  func testBigUIntToData_LargeValue() throws {
    let session = try SRPSession.create()
    // Test with a value larger than 256 bits
    let value = BigUInt(1) << 512
    let data = session.bigUIntToData(value)
    let restored = BigUInt(data)
    XCTAssertEqual(value, restored)
  }

  /// Hex username format.
  func testUsername_HexFormat() throws {
    let session = try SRPSession.create(useBase64: false)
    XCTAssertTrue(session.username.hasPrefix("0x"))
    // 16 random bytes → 32 hex chars + "0x" prefix = 34 chars
    XCTAssertEqual(session.username.count, 34)
  }

  /// Base64 username format.
  func testUsername_Base64Format() throws {
    let session = try SRPSession.create(useBase64: true)
    XCTAssertFalse(session.username.hasPrefix("0x"))
    // 16 bytes → 24 base64 chars (with padding)
    XCTAssertEqual(session.username.count, 24)
  }

  /// Server public key that is a multiple of N should be rejected.
  func testSetServerPublicKey_RejectsMultipleOfN() throws {
    let session = try SRPSession.create()
    XCTAssertThrowsError(
      try session.setServerPublicKey(SRPConstants.groupPrime, salt: BigUInt(1234))
    )
    XCTAssertThrowsError(
      try session.setServerPublicKey(SRPConstants.groupPrime * 2, salt: BigUInt(1234))
    )
  }

  /// computeM and computeServerVerifier should throw without handshake.
  func testComputeM_WithoutHandshake_Throws() throws {
    let session = try SRPSession.create()
    XCTAssertThrowsError(try session.computeM())
  }

  func testComputeServerVerifier_WithoutHandshake_Throws() throws {
    let session = try SRPSession.create()
    XCTAssertThrowsError(try session.computeServerVerifier(Data()))
  }

  // MARK: - Leading-zero and fixed-width tests

  /// encryptionKeyData must always return exactly 32 bytes (AES-256) even when
  /// the SHA-256 shared key starts with leading zero bytes.
  func testEncryptionKeyData_LeadingZeroKey() throws {
    // Shared key with leading zero byte — BigUInt.serialize() strips it
    var keyBytes = [UInt8](repeating: 0, count: 32)
    keyBytes[0] = 0x00
    keyBytes[1] = 0x01
    let session = SRPSession.restore(
      username: "test", sharedKey: BigUInt(Data(keyBytes)), useBase64: true)
    let encKey = try session.encryptionKeyData()
    XCTAssertEqual(encKey.count, 32, "Encryption key must be exactly 32 bytes (AES-256)")
    // First byte must be 0x00 (the leading zero that serialize() would strip)
    XCTAssertEqual(encKey[0], 0x00)
    XCTAssertEqual(encKey[1], 0x01)
  }

  /// bigUIntToFixedData must pad to the requested size.
  func testBigUIntToFixedData_PadsCorrectly() throws {
    let session = try SRPSession.create()
    let value = BigUInt(Data([0x01, 0x02]))
    let fixed = session.bigUIntToFixedData(value, size: 4)
    XCTAssertEqual(fixed, Data([0x00, 0x00, 0x01, 0x02]))
  }

  /// bigUIntToFixedData with value that fills the size exactly.
  func testBigUIntToFixedData_ExactSize() throws {
    let session = try SRPSession.create()
    let value = BigUInt(Data([0xAB, 0xCD, 0xEF, 0x01]))
    let fixed = session.bigUIntToFixedData(value, size: 4)
    XCTAssertEqual(fixed, Data([0xAB, 0xCD, 0xEF, 0x01]))
  }

  /// Pad helper: data shorter than target length gets zero-padded on the left.
  func testPad_ShorterData() throws {
    let session = try SRPSession.create()
    let data = Data([0x01, 0x02])
    let padded = session.pad(data, to: 4)
    XCTAssertEqual(padded, Data([0x00, 0x00, 0x01, 0x02]))
  }

  /// Pad helper: data longer than target gets truncated to prefix.
  func testPad_LongerData() throws {
    let session = try SRPSession.create()
    let data = Data([0x01, 0x02, 0x03, 0x04])
    let padded = session.pad(data, to: 2)
    XCTAssertEqual(padded, Data([0x01, 0x02]))
  }
}
