import Foundation

/// Configure a sockaddr_un and call `body` with a pointer rebound to sockaddr + length.
/// Shared by both UnixSocketServer and UnixSocketClient.
func withUnixSocketAddress<R>(
  path: String, body: (UnsafePointer<sockaddr>, socklen_t) -> R
) -> R {
  var addr = sockaddr_un()
  addr.sun_family = sa_family_t(AF_UNIX)
  let pathBytes = path.utf8CString
  withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
    let raw = UnsafeMutableRawPointer(ptr)
    pathBytes.withUnsafeBufferPointer { buf in
      raw.copyMemory(from: buf.baseAddress!, byteCount: buf.count)
    }
  }
  let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
  return withUnsafePointer(to: &addr) { ptr in
    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
      body(sockPtr, addrLen)
    }
  }
}

// MARK: - Length-prefixed I/O helpers (4-byte big-endian prefix)

/// Send all bytes in `data` over `fd`. Returns false on error.
func socketSendAll(fd: Int32, data: Data) -> Bool {
  data.withUnsafeBytes { buf in
    guard let base = buf.baseAddress else { return false }
    var sent = 0
    while sent < data.count {
      let n = send(fd, base + sent, data.count - sent, 0)
      if n <= 0 { return false }
      sent += n
    }
    return true
  }
}

/// Receive exactly `count` bytes from `fd` into `buffer`. Returns false on error/EOF.
func socketRecvAll(fd: Int32, buffer: inout [UInt8], count: Int) -> Bool {
  var total = 0
  while total < count {
    let n = buffer.withUnsafeMutableBytes { buf in
      recv(fd, buf.baseAddress! + total, count - total, 0)
    }
    if n <= 0 { return false }
    total += n
  }
  return true
}

/// Read a length-prefixed message from `fd`. Returns nil on EOF/error.
func socketReadMessage(fd: Int32) -> Data? {
  var lengthBuf = [UInt8](repeating: 0, count: 4)
  guard socketRecvAll(fd: fd, buffer: &lengthBuf, count: 4) else { return nil }
  let length = Int(
    UInt32(lengthBuf[0]) << 24 | UInt32(lengthBuf[1]) << 16
      | UInt32(lengthBuf[2]) << 8 | UInt32(lengthBuf[3]))
  guard length > 0, length < 10_000_000 else { return nil }
  var buf = [UInt8](repeating: 0, count: length)
  guard socketRecvAll(fd: fd, buffer: &buf, count: length) else { return nil }
  return Data(buf)
}

/// Write a length-prefixed message to `fd`.
func socketWriteMessage(fd: Int32, data: Data) {
  var length = UInt32(data.count).bigEndian
  let lengthData = Swift.withUnsafeBytes(of: &length) { Data($0) }
  _ = socketSendAll(fd: fd, data: lengthData)
  _ = socketSendAll(fd: fd, data: data)
}

/// Unix domain socket client for communicating with the Passwords daemon.
public enum UnixSocketClient {

  /// Send a message to the daemon and receive a response.
  /// Protocol: 4-byte big-endian length prefix + JSON payload.
  public static func sendMessage(_ data: Data, socketPath: String) throws -> Data {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
      throw UnixSocketError.socketCreationFailed(errno)
    }
    defer { close(fd) }

    let connectResult = withUnixSocketAddress(path: socketPath) { sockPtr, addrLen in
      connect(fd, sockPtr, addrLen)
    }
    guard connectResult == 0 else {
      throw UnixSocketError.connectFailed(errno)
    }

    socketWriteMessage(fd: fd, data: data)

    guard let response = socketReadMessage(fd: fd) else {
      throw UnixSocketError.communicationFailed
    }
    return response
  }

  /// Check if a daemon is alive at the given socket path.
  public static func isAlive(socketPath: String) -> Bool {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return false }
    defer { close(fd) }

    let result = withUnixSocketAddress(path: socketPath) { sockPtr, addrLen in
      connect(fd, sockPtr, addrLen)
    }
    return result == 0
  }
}
