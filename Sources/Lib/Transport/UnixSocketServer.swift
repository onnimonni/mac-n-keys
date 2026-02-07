import Foundation

/// Unix domain socket server for the Passwords daemon bridge.
/// Uses POSIX sockets directly — no Network framework dependency.
public final class UnixSocketServer: @unchecked Sendable {

  public let socketPath: String
  private var serverFD: Int32 = -1
  private let queue = DispatchQueue(label: "mac-n-keys.daemon", attributes: .concurrent)

  public init(socketPath: String) {
    self.socketPath = socketPath
  }

  deinit {
    stop()
  }

  /// Start listening on the Unix domain socket.
  /// Creates parent directory with 0700 if needed. Removes stale socket files.
  public func start(handler: @escaping @Sendable (_ requestData: Data) throws -> Data) throws {
    let dir = (socketPath as NSString).deletingLastPathComponent
    // Set restrictive umask before creating directory so it is born with 0700
    let oldMask = umask(0o077)
    defer { umask(oldMask) }
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    // Ensure directory is only accessible by owner (in case it already existed)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o700], ofItemAtPath: dir)

    // Remove stale socket if it exists
    if FileManager.default.fileExists(atPath: socketPath) {
      // Try connecting to see if a daemon is already running
      if UnixSocketClient.isAlive(socketPath: socketPath) {
        throw UnixSocketError.alreadyRunning
      }
      try FileManager.default.removeItem(atPath: socketPath)
    }

    serverFD = socket(AF_UNIX, SOCK_STREAM, 0)
    guard serverFD >= 0 else {
      throw UnixSocketError.socketCreationFailed(errno)
    }

    guard socketPath.utf8CString.count <= 104 else {
      close(serverFD)
      serverFD = -1
      throw UnixSocketError.pathTooLong
    }

    let bindResult = withUnixSocketAddress(path: socketPath) { sockPtr, addrLen in
      bind(serverFD, sockPtr, addrLen)
    }
    guard bindResult == 0 else {
      let err = errno
      close(serverFD)
      serverFD = -1
      throw UnixSocketError.bindFailed(err)
    }

    // Set socket file permissions to owner-only
    chmod(socketPath, 0o600)

    guard listen(serverFD, 5) == 0 else {
      let err = errno
      close(serverFD)
      serverFD = -1
      unlink(socketPath)
      throw UnixSocketError.listenFailed(err)
    }

    // Accept loop on background queue
    queue.async { [weak self] in
      self?.acceptLoop(handler: handler)
    }
  }

  /// Stop the server and clean up the socket file.
  public func stop() {
    if serverFD >= 0 {
      close(serverFD)
      serverFD = -1
    }
    unlink(socketPath)
  }

  private func acceptLoop(handler: @escaping @Sendable (_ requestData: Data) throws -> Data) {
    while serverFD >= 0 {
      let clientFD = accept(serverFD, nil, nil)
      guard clientFD >= 0 else { break }
      queue.async {
        self.handleClient(clientFD, handler: handler)
      }
    }
  }

  private func handleClient(_ fd: Int32, handler: (_ requestData: Data) throws -> Data) {
    defer { close(fd) }
    // Read length-prefixed message: 4-byte BE length + JSON
    while let requestData = socketReadMessage(fd: fd) {
      do {
        let responseData = try handler(requestData)
        socketWriteMessage(fd: fd, data: responseData)
      } catch {
        let errorJSON = (try? JSONSerialization.data(
          withJSONObject: ["error": "\(error)"])) ?? Data()
        socketWriteMessage(fd: fd, data: errorJSON)
      }
    }
  }
}

public enum UnixSocketError: LocalizedError {
  case socketCreationFailed(Int32)
  case bindFailed(Int32)
  case listenFailed(Int32)
  case connectFailed(Int32)
  case pathTooLong
  case alreadyRunning
  case communicationFailed

  public var errorDescription: String? {
    switch self {
    case .socketCreationFailed(let e): "Socket creation failed (errno: \(e))"
    case .bindFailed(let e): "Socket bind failed (errno: \(e))"
    case .listenFailed(let e): "Socket listen failed (errno: \(e))"
    case .connectFailed(let e): "Socket connect failed (errno: \(e))"
    case .pathTooLong: "Socket path exceeds sockaddr_un limit (104 bytes)"
    case .alreadyRunning: "Daemon is already running"
    case .communicationFailed: "Socket communication failed"
    }
  }
}
