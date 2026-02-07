import Foundation

/// Unix socket bridge daemon connecting clients to the NativeMessaging helper.
public final class DaemonConnection: @unchecked Sendable {

  /// Default socket path: ~/.mac-n-keys/daemon.sock
  public static var defaultSocketPath: String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return "\(home)/.mac-n-keys/daemon.sock"
  }

  private let helper: NativeMessaging
  private var server: UnixSocketServer?

  public init() throws {
    self.helper = try NativeMessaging()
  }

  /// Start listening on Unix domain socket.
  public func start(socketPath: String? = nil) throws {
    let path = socketPath ?? Self.defaultSocketPath
    let srv = UnixSocketServer(socketPath: path)
    self.server = srv

    try srv.start { [weak self] requestData in
      guard let self else { throw TransportError.invalidResponse }
      let message = try JSONSerialization.jsonObject(with: requestData)
      let response = try self.helper.sendMessage(message)
      return try JSONSerialization.data(withJSONObject: response)
    }
  }

  public func stop() {
    server?.stop()
  }

  /// Send a single message to the daemon and get the response.
  public static func sendMessage(
    _ message: [String: Any], socketPath: String
  ) throws -> [String: Any] {
    let data = try JSONSerialization.data(withJSONObject: message)
    let responseData = try UnixSocketClient.sendMessage(data, socketPath: socketPath)
    guard let result = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
      throw TransportError.invalidResponse
    }
    return result
  }
}
