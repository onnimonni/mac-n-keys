import BigInt
import Foundation
import XCTest

@testable import Lib

final class PasswordsProtocolTests: XCTestCase {

  // MARK: - Enum raw values

  func testPasswordsCommand_RawValues() {
    XCTAssertEqual(PasswordsCommand.end.rawValue, 0)
    XCTAssertEqual(PasswordsCommand.handshake.rawValue, 2)
    XCTAssertEqual(PasswordsCommand.getLoginNamesForURL.rawValue, 4)
    XCTAssertEqual(PasswordsCommand.getPasswordForLoginName.rawValue, 5)
    XCTAssertEqual(PasswordsCommand.getCapabilities.rawValue, 14)
    XCTAssertEqual(PasswordsCommand.getOneTimeCodes.rawValue, 16)
    XCTAssertEqual(PasswordsCommand.didFillOneTimeCode.rawValue, 17)
  }

  func testMSGType_RawValues() {
    XCTAssertEqual(MSGType.clientKeyExchange.rawValue, 0)
    XCTAssertEqual(MSGType.serverKeyExchange.rawValue, 1)
    XCTAssertEqual(MSGType.clientVerification.rawValue, 2)
    XCTAssertEqual(MSGType.serverVerification.rawValue, 3)
  }

  func testPasswordsAction_RawValues() {
    XCTAssertEqual(PasswordsAction.search.rawValue, 2)
    XCTAssertEqual(PasswordsAction.ghostSearch.rawValue, 5)
  }

  // MARK: - getCapabilities

  func testGetCapabilities_ReturnsCorrectCommand() {
    let msg = PasswordsMessages.getCapabilities()
    XCTAssertEqual(msg["cmd"] as? Int, PasswordsCommand.getCapabilities.rawValue)
    XCTAssertEqual(msg.count, 1)
  }

  // MARK: - requestChallenge

  func testRequestChallenge_ContainsHandshakeCommand() throws {
    let session = try SRPSession.create(useBase64: true)
    let msg = try PasswordsMessages.requestChallenge(session: session)

    XCTAssertEqual(msg["cmd"] as? Int, PasswordsCommand.handshake.rawValue)
  }

  func testRequestChallenge_MsgContainsRequiredFields() throws {
    let session = try SRPSession.create(useBase64: true)
    let msg = try PasswordsMessages.requestChallenge(session: session)

    let inner = msg["msg"] as? [String: Any]
    XCTAssertNotNil(inner)
    XCTAssertNotNil(inner?["QID"])
    XCTAssertNotNil(inner?["PAKE"])
    XCTAssertNotNil(inner?["HSTBRSR"])
    XCTAssertEqual(inner?["QID"] as? String, "m0")
    XCTAssertEqual(inner?["HSTBRSR"] as? String, "Arc")
  }

  func testRequestChallenge_PAKEContainsClientKey() throws {
    let session = try SRPSession.create(useBase64: true)
    let msg = try PasswordsMessages.requestChallenge(session: session)

    let inner = msg["msg"] as? [String: Any]
    let pakeBase64 = inner?["PAKE"] as? String
    XCTAssertNotNil(pakeBase64)

    let pakeData = Data(base64Encoded: pakeBase64!)!
    let pake = try JSONSerialization.jsonObject(with: pakeData) as! [String: Any]

    XCTAssertEqual(pake["TID"] as? String, session.username)
    XCTAssertEqual(pake["MSG"] as? Int, MSGType.clientKeyExchange.rawValue)
    XCTAssertNotNil(pake["A"])
    XCTAssertNotNil(pake["VER"])
    XCTAssertNotNil(pake["PROTO"])
  }

  // MARK: - verifyChallenge

  func testVerifyChallenge_ContainsHandshakeCommand() throws {
    let session = try SRPSession.create(useBase64: true)
    // verifyChallenge needs M data; provide dummy data
    let dummyM = Data(repeating: 0xAB, count: 32)
    let msg = try PasswordsMessages.verifyChallenge(session: session, m: dummyM)

    XCTAssertEqual(msg["cmd"] as? Int, PasswordsCommand.handshake.rawValue)
  }

  func testVerifyChallenge_PAKEContainsClientVerification() throws {
    let session = try SRPSession.create(useBase64: true)
    let dummyM = Data(repeating: 0xCD, count: 32)
    let msg = try PasswordsMessages.verifyChallenge(session: session, m: dummyM)

    let inner = msg["msg"] as? [String: Any]
    XCTAssertEqual(inner?["QID"] as? String, "m2")

    let pakeBase64 = inner?["PAKE"] as? String
    XCTAssertNotNil(pakeBase64)

    let pakeData = Data(base64Encoded: pakeBase64!)!
    let pake = try JSONSerialization.jsonObject(with: pakeData) as! [String: Any]

    XCTAssertEqual(pake["TID"] as? String, session.username)
    XCTAssertEqual(pake["MSG"] as? Int, MSGType.clientVerification.rawValue)
    XCTAssertNotNil(pake["M"])
  }

  // MARK: - Encrypted payload methods (require shared key)

  func testGetLoginNamesForURL_Structure() throws {
    let sharedKey = BigUInt(Data(repeating: 0x42, count: 32))
    let session = SRPSession.restore(username: "testuser", sharedKey: sharedKey, useBase64: true)

    let msg = try PasswordsMessages.getLoginNamesForURL(session: session, url: "https://github.com")

    XCTAssertEqual(msg["cmd"] as? Int, PasswordsCommand.getLoginNamesForURL.rawValue)
    XCTAssertEqual(msg["tabId"] as? Int, 1)
    XCTAssertEqual(msg["frameId"] as? Int, 1)
    XCTAssertEqual(msg["url"] as? String, "https://github.com")
    XCTAssertNotNil(msg["payload"] as? String)
  }

  func testGetLoginNamesForURL_PayloadContainsSMSG() throws {
    let sharedKey = BigUInt(Data(repeating: 0x42, count: 32))
    let session = SRPSession.restore(username: "testuser", sharedKey: sharedKey, useBase64: true)

    let msg = try PasswordsMessages.getLoginNamesForURL(session: session, url: "https://example.com")
    let payloadStr = msg["payload"] as! String
    let payloadData = Data(payloadStr.utf8)
    let payload = try JSONSerialization.jsonObject(with: payloadData) as! [String: Any]

    XCTAssertEqual(payload["QID"] as? String, "CmdGetLoginNames4URL")
    let smsg = payload["SMSG"] as? [String: Any]
    XCTAssertNotNil(smsg)
    let tid = smsg?["TID"] as? String
    XCTAssertEqual(tid, "testuser")
    XCTAssertNotNil(smsg?["SDATA"])
  }

  func testGetPasswordForURL_Structure() throws {
    let sharedKey = BigUInt(Data(repeating: 0x42, count: 32))
    let session = SRPSession.restore(username: "testuser", sharedKey: sharedKey, useBase64: true)

    let msg = try PasswordsMessages.getPasswordForURL(
      session: session, url: "https://github.com", loginName: "myuser")

    XCTAssertEqual(msg["cmd"] as? Int, PasswordsCommand.getPasswordForLoginName.rawValue)
    XCTAssertEqual(msg["tabId"] as? Int, 0)
    XCTAssertEqual(msg["url"] as? String, "https://github.com")
    XCTAssertNotNil(msg["payload"] as? String)
  }

  func testGetOTPForURL_Structure() throws {
    let sharedKey = BigUInt(Data(repeating: 0x42, count: 32))
    let session = SRPSession.restore(username: "testuser", sharedKey: sharedKey, useBase64: true)

    let msg = try PasswordsMessages.getOTPForURL(session: session, url: "https://github.com")

    XCTAssertEqual(msg["cmd"] as? Int, PasswordsCommand.didFillOneTimeCode.rawValue)
    XCTAssertNotNil(msg["payload"] as? String)
  }

  func testEncryptedPayload_ProducesValidStructure() throws {
    let sharedKey = BigUInt(Data(repeating: 0x42, count: 32))
    let session = SRPSession.restore(username: "testuser", sharedKey: sharedKey, useBase64: true)

    let msg = try PasswordsMessages.getLoginNamesForURL(session: session, url: "https://test.com")
    let payloadStr = msg["payload"] as! String
    let payloadData = Data(payloadStr.utf8)
    let payload = try JSONSerialization.jsonObject(with: payloadData) as! [String: Any]

    let smsg = payload["SMSG"] as! [String: Any]
    let sdata = smsg["SDATA"] as! String

    // Verify SDATA is valid base64 and contains encrypted data
    // (encrypt wire format: ciphertext + tag(16) + iv(12), minimum 28 bytes)
    let encryptedData = session.deserialize(sdata)
    XCTAssertGreaterThanOrEqual(encryptedData.count, 28,
      "Encrypted payload should be at least 28 bytes (16 tag + 12 iv)")
  }

  // MARK: - Hex vs Base64 serialization modes

  func testRequestChallenge_HexMode() throws {
    let session = try SRPSession.create(useBase64: false)
    let msg = try PasswordsMessages.requestChallenge(session: session)

    let inner = msg["msg"] as? [String: Any]
    let pakeBase64 = inner?["PAKE"] as? String
    let pakeData = Data(base64Encoded: pakeBase64!)!
    let pake = try JSONSerialization.jsonObject(with: pakeData) as! [String: Any]

    // In hex mode, "A" should be a hex string with 0x prefix
    let aStr = pake["A"] as! String
    XCTAssertTrue(aStr.hasPrefix("0x"), "Hex mode should use 0x prefix")
    let hex = String(aStr.dropFirst(2))
    XCTAssertTrue(hex.allSatisfy { "0123456789abcdef".contains($0) })
  }
}
