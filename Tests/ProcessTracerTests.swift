import XCTest

@testable import Lib

final class ProcessTracerTests: XCTestCase {
  func testCallerDescription_ReturnsNonEmpty() {
    let desc = ProcessTracer.callerDescription()
    XCTAssertFalse(desc.isEmpty)
    XCTAssertTrue(desc.contains("pid"))
  }

  func testParentProcess_HasValidPID() {
    let parent = ProcessTracer.parentProcess()
    XCTAssertGreaterThan(parent.pid, 0)
  }

  func testProcessInfo_ForCurrentPID() {
    let pid = ProcessInfo.processInfo.processIdentifier
    let info = ProcessTracer.processInfo(for: pid)
    XCTAssertEqual(info.pid, pid)
    XCTAssertFalse(info.name.isEmpty)
  }

  func testProcessChain_FromCurrentPID() {
    let pid = ProcessInfo.processInfo.processIdentifier
    let chain = ProcessTracer.processChain(from: pid)
    XCTAssertGreaterThanOrEqual(chain.count, 1)
    XCTAssertEqual(chain.first?.pid, pid)
  }
}
