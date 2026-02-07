import Foundation
import Synchronization
import XCTest

@testable import Lib

final class UnixSocketIntegrationTests: XCTestCase {

  private var tempDir: String!

  override func setUp() {
    super.setUp()
    // Keep path short — Unix sockets have a 104-byte path limit on macOS
    let shortID = UUID().uuidString.prefix(8)
    tempDir = "/tmp/mnk-\(shortID)"
  }

  override func tearDown() {
    if let dir = tempDir {
      try? FileManager.default.removeItem(atPath: dir)
    }
    super.tearDown()
  }

  private var socketPath: String {
    "\(tempDir!)/test.sock"
  }

  // MARK: - Server/Client round-trip

  func testServerClient_RoundTrip() throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in
      // Echo handler: return whatever was sent
      return request
    }
    defer { server.stop() }

    // Give server time to start listening
    Thread.sleep(forTimeInterval: 0.05)

    let message = Data("{\"hello\":\"world\"}".utf8)
    let response = try UnixSocketClient.sendMessage(message, socketPath: socketPath)
    XCTAssertEqual(response, message)
  }

  func testServerClient_JSONRoundTrip() throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in
      // Parse JSON, add a field, return
      var obj = try JSONSerialization.jsonObject(with: request) as! [String: Any]
      obj["response"] = "ok"
      return try JSONSerialization.data(withJSONObject: obj)
    }
    defer { server.stop() }

    Thread.sleep(forTimeInterval: 0.05)

    let request = try JSONSerialization.data(withJSONObject: ["cmd": 14])
    let responseData = try UnixSocketClient.sendMessage(request, socketPath: socketPath)
    let response = try JSONSerialization.jsonObject(with: responseData) as! [String: Any]

    XCTAssertEqual(response["cmd"] as? Int, 14)
    XCTAssertEqual(response["response"] as? String, "ok")
  }

  func testServerClient_MultipleSequentialMessages() throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in request }
    defer { server.stop() }

    Thread.sleep(forTimeInterval: 0.05)

    for i in 0..<5 {
      let msg = Data("message-\(i)".utf8)
      let resp = try UnixSocketClient.sendMessage(msg, socketPath: socketPath)
      XCTAssertEqual(resp, msg, "Message \(i) round-trip failed")
    }
  }

  func testServerClient_LargePayload() throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in request }
    defer { server.stop() }

    Thread.sleep(forTimeInterval: 0.05)

    // 1MB payload
    let largeData = Data(repeating: 0x42, count: 1_000_000)
    let response = try UnixSocketClient.sendMessage(largeData, socketPath: socketPath)
    XCTAssertEqual(response.count, largeData.count)
    XCTAssertEqual(response, largeData)
  }

  func testServerClient_HandlerError_ReturnsErrorJSON() throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { _ in
      throw NSError(domain: "test", code: 42, userInfo: [NSLocalizedDescriptionKey: "test error"])
    }
    defer { server.stop() }

    Thread.sleep(forTimeInterval: 0.05)

    let msg = Data("trigger-error".utf8)
    let responseData = try UnixSocketClient.sendMessage(msg, socketPath: socketPath)
    let response = try JSONSerialization.jsonObject(with: responseData) as! [String: Any]
    XCTAssertNotNil(response["error"])
  }

  // MARK: - isAlive

  func testIsAlive_NoServer_ReturnsFalse() {
    let nonexistent = tempDir + "/nonexistent.sock"
    XCTAssertFalse(UnixSocketClient.isAlive(socketPath: nonexistent))
  }

  func testIsAlive_WithServer_ReturnsTrue() throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in request }
    defer { server.stop() }

    Thread.sleep(forTimeInterval: 0.05)
    XCTAssertTrue(UnixSocketClient.isAlive(socketPath: socketPath))
  }

  func testIsAlive_StoppedServer_ReturnsFalse() throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in request }
    server.stop()

    Thread.sleep(forTimeInterval: 0.05)
    XCTAssertFalse(UnixSocketClient.isAlive(socketPath: socketPath))
  }

  // MARK: - Server lifecycle

  func testServer_AlreadyRunning_Throws() throws {
    let server1 = UnixSocketServer(socketPath: socketPath)
    try server1.start { request in request }
    defer { server1.stop() }

    Thread.sleep(forTimeInterval: 0.05)

    let server2 = UnixSocketServer(socketPath: socketPath)
    XCTAssertThrowsError(try server2.start { request in request }) { error in
      guard let socketErr = error as? UnixSocketError else {
        XCTFail("Expected UnixSocketError, got \(error)")
        return
      }
      XCTAssertEqual(socketErr.localizedDescription, UnixSocketError.alreadyRunning.localizedDescription)
    }
  }

  func testServer_StaleSocket_IsRemoved() throws {
    // Create a stale socket file (just a regular file, not a real socket)
    try FileManager.default.createDirectory(
      atPath: tempDir, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: socketPath, contents: nil)
    XCTAssertTrue(FileManager.default.fileExists(atPath: socketPath))

    // Server should remove the stale file and start successfully
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in request }
    defer { server.stop() }

    Thread.sleep(forTimeInterval: 0.05)
    XCTAssertTrue(UnixSocketClient.isAlive(socketPath: socketPath))
  }

  func testServer_CreatesParentDirectory() throws {
    let nestedPath = tempDir + "/nested/deep/test.sock"

    let server = UnixSocketServer(socketPath: nestedPath)
    try server.start { request in request }
    defer { server.stop() }

    // Parent directory should exist
    var isDir: ObjCBool = false
    let parentExists = FileManager.default.fileExists(
      atPath: tempDir + "/nested/deep", isDirectory: &isDir)
    XCTAssertTrue(parentExists)
    XCTAssertTrue(isDir.boolValue)
  }

  func testServer_DirectoryPermissions_OwnerOnly() throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in request }
    defer { server.stop() }

    let dir = (socketPath as NSString).deletingLastPathComponent
    let attrs = try FileManager.default.attributesOfItem(atPath: dir)
    let perms = attrs[.posixPermissions] as! Int
    XCTAssertEqual(perms, 0o700, "Socket directory should be owner-only (0700)")
  }

  // MARK: - Client errors

  func testClient_NoServer_ThrowsConnectFailed() {
    let nonexistent = tempDir + "/nonexistent.sock"
    XCTAssertThrowsError(
      try UnixSocketClient.sendMessage(Data("test".utf8), socketPath: nonexistent)
    ) { error in
      if let socketErr = error as? UnixSocketError {
        switch socketErr {
        case .connectFailed: break  // expected
        default: XCTFail("Expected connectFailed, got \(socketErr)")
        }
      }
    }
  }

  // MARK: - Concurrent clients

  func testServer_ConcurrentClients() async throws {
    let server = UnixSocketServer(socketPath: socketPath)
    try server.start { request in
      // Simulate some work
      Thread.sleep(forTimeInterval: 0.01)
      return request
    }
    defer { server.stop() }

    try await Task.sleep(for: .milliseconds(50))

    let clientCount = 10
    let successCount = Mutex(0)
    let path = socketPath

    await withTaskGroup(of: Bool.self) { group in
      for i in 0..<clientCount {
        group.addTask {
          let msg = Data("client-\(i)".utf8)
          guard let resp = try? UnixSocketClient.sendMessage(msg, socketPath: path) else {
            return false
          }
          return resp == msg
        }
      }
      for await result in group {
        if result {
          successCount.withLock { $0 += 1 }
        }
      }
    }
    XCTAssertEqual(successCount.withLock { $0 }, clientCount)
  }
}
