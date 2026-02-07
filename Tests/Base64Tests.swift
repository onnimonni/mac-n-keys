import XCTest

@testable import Lib

final class Base64Tests: XCTestCase {
  func testDataInitBase64RawEncoded_NeedsNoPad() throws {
    XCTAssertEqual(
      Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
      Data(base64RawEncoded: "AQIDBAUG"))
  }

  func testDataInitBase64RawEncoded_Needs1Pad() throws {
    XCTAssertEqual(
      Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
      Data(base64RawEncoded: "AQIDBAUGBwg"))
  }

  func testDataInitBase64RawEncoded_Needs2Pads() throws {
    XCTAssertEqual(
      Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
      Data(base64RawEncoded: "AQIDBAUGBw"))
  }

  func testDataInitBase64RawEncoded_HasPad() throws {
    XCTAssertEqual(
      nil,
      Data(base64RawEncoded: "AQIDBAUGBwg="))
  }

  func testDataInit_InvalidBase64() throws {
    XCTAssertEqual(
      nil,
      Data(base64RawEncoded: "A_QIDBAUG"))
  }

  func testDataBase64RawEncodedData() throws {
    XCTAssertEqual(
      Data("AQIDBAUGBw".utf8),
      Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]).base64RawEncodedData())
  }
}
