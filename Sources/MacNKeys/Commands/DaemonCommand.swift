import ArgumentParser
import Foundation
import Lib

struct DaemonCommand: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "daemon",
    abstract: "Run the Passwords.app bridge daemon"
  )

  @Option(help: "Unix socket path (default: ~/.mac-n-keys/daemon.sock)")
  var socket: String?

  func run() async throws {
    let daemon = try DaemonConnection()
    let path = socket ?? DaemonConnection.defaultSocketPath
    try daemon.start(socketPath: path)
    print("Daemon listening on \(path)")

    // Clean up socket on signals
    let signalSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    signal(SIGINT, SIG_IGN)
    signalSource.setEventHandler {
      daemon.stop()
      Foundation.exit(0)
    }
    signalSource.resume()

    // Keep running
    await withUnsafeContinuation { (_: UnsafeContinuation<Void, Never>) in }
  }
}
