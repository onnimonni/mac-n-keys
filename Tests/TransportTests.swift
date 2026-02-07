import Foundation
import XCTest

@testable import Lib

final class DaemonConnectionTests: XCTestCase {

  func testDefaultSocketPath_ContainsMacNKeys() {
    let path = DaemonConnection.defaultSocketPath
    XCTAssertTrue(path.contains(".mac-n-keys/"), "Socket path should use .mac-n-keys directory")
  }

  func testDefaultSocketPath_EndsWithDaemonSock() {
    let path = DaemonConnection.defaultSocketPath
    XCTAssertTrue(path.hasSuffix("/daemon.sock"))
  }

  func testDefaultSocketPath_StartsWithHome() {
    let path = DaemonConnection.defaultSocketPath
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    XCTAssertTrue(path.hasPrefix(home))
  }

  func testDefaultSocketPath_IsUnderSocketLengthLimit() {
    // Unix domain sockets have a 104-byte path limit on macOS
    let path = DaemonConnection.defaultSocketPath
    XCTAssertLessThanOrEqual(path.utf8CString.count, 104,
      "Default socket path must fit in sockaddr_un (104 bytes)")
  }
}

final class DaemonConnectionIntegrationTests: XCTestCase {

  private var tempDir: String!

  override func setUp() {
    super.setUp()
    let shortID = UUID().uuidString.prefix(8)
    tempDir = "/tmp/mnk-d-\(shortID)"
  }

  override func tearDown() {
    if let dir = tempDir {
      try? FileManager.default.removeItem(atPath: dir)
    }
    super.tearDown()
  }

  /// DaemonConnection.sendMessage talks to a UnixSocketServer — test the
  /// static client path independently of NativeMessaging (which needs the
  /// real PasswordManagerBrowserExtensionHelper).
  func testSendMessage_WithMockServer() throws {
    let socketPath = tempDir + "/daemon.sock"
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in
      // Wrap in {"payload": {original}} to mimic real daemon
      let obj = try JSONSerialization.jsonObject(with: request)
      let response: [String: Any] = ["payload": obj, "status": "ok"]
      return try JSONSerialization.data(withJSONObject: response)
    }
    defer { server.stop() }

    Thread.sleep(forTimeInterval: 0.05)

    let msg: [String: Any] = ["cmd": 14]
    let resp = try DaemonConnection.sendMessage(msg, socketPath: socketPath)

    XCTAssertEqual(resp["status"] as? String, "ok")
    let payload = resp["payload"] as? [String: Any]
    XCTAssertEqual(payload?["cmd"] as? Int, 14)
  }
}

final class TransportErrorTests: XCTestCase {

  func testTransportError_Descriptions() {
    let errors: [(TransportError, String)] = [
      (.helperNotFound, "PasswordManagerBrowserExtensionHelper not found"),
      (.helperCommunicationFailed, "Failed to communicate with helper"),
      (.helperPathUntrusted("/tmp/evil"), "Helper path untrusted: /tmp/evil (must be under /System/ or /Library/)"),
      (.invalidResponse, "Invalid response from helper"),
    ]

    for (error, expected) in errors {
      XCTAssertEqual(error.localizedDescription, expected)
    }
  }
}

final class UnixSocketErrorTests: XCTestCase {

  func testUnixSocketError_PathTooLong() {
    let err = UnixSocketError.pathTooLong
    XCTAssertEqual(err.localizedDescription, "Socket path exceeds sockaddr_un limit (104 bytes)")
  }

  func testUnixSocketError_AlreadyRunning() {
    let err = UnixSocketError.alreadyRunning
    XCTAssertEqual(err.localizedDescription, "Daemon is already running")
  }

  func testUnixSocketError_CommunicationFailed() {
    let err = UnixSocketError.communicationFailed
    XCTAssertEqual(err.localizedDescription, "Socket communication failed")
  }

  func testUnixSocketError_SocketCreationFailed() {
    let err = UnixSocketError.socketCreationFailed(13)
    XCTAssertTrue(err.localizedDescription.contains("13"))
  }

  func testUnixSocketError_BindFailed() {
    let err = UnixSocketError.bindFailed(48)
    XCTAssertTrue(err.localizedDescription.contains("48"))
  }
}
