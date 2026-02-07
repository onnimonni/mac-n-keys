import Foundation
import XCTest

@testable import Lib

final class ExtensionsTests: XCTestCase {

  // MARK: - Data.hexString

  func testHexString_EmptyData() {
    XCTAssertEqual(Data().hexString, "")
  }

  func testHexString_SingleByte() {
    XCTAssertEqual(Data([0xff]).hexString, "ff")
    XCTAssertEqual(Data([0x00]).hexString, "00")
    XCTAssertEqual(Data([0x0a]).hexString, "0a")
  }

  func testHexString_MultipleBytesLowercase() {
    let data = Data([0xDE, 0xAD, 0xBE, 0xEF])
    XCTAssertEqual(data.hexString, "deadbeef")
  }

  func testHexString_AllZeros() {
    let data = Data(repeating: 0x00, count: 4)
    XCTAssertEqual(data.hexString, "00000000")
  }

  func testHexString_SequentialBytes() {
    let data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    XCTAssertEqual(data.hexString, "0123456789abcdef")
  }

  func testHexString_Length_IsTwiceByteCount() {
    let data = Data(repeating: 0x42, count: 16)
    XCTAssertEqual(data.hexString.count, 32)
  }

  // MARK: - makeAccessControl

  func testMakeAccessControl_ValidFlags() throws {
    let access = try makeAccessControl(flags: .privateKeyUsage)
    XCTAssertNotNil(access)
  }

  func testMakeAccessControl_UserPresence() throws {
    let access = try makeAccessControl(flags: [.userPresence, .privateKeyUsage])
    XCTAssertNotNil(access)
  }
}
