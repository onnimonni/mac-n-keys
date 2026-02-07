import ArgumentParser
import Lib

struct SSHGroup: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "ssh",
    abstract: "Manage SSH keys in the Secure Enclave",
    subcommands: [
      SSHListCommand.self,
      SSHCreateCommand.self,
      SSHPublicKeyCommand.self,
      SSHSignCommand.self,
      SSHDeleteCommand.self,
    ],
    defaultSubcommand: SSHListCommand.self
  )
}

struct SSHListCommand: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "list",
    abstract: "List all SSH keys"
  )

  @Flag(name: .shortAndLong, help: "Show detailed info")
  var verbose = false

  func run() throws {
    let keys = SecureEnclaveKeys.list()
    if keys.isEmpty {
      print("No keys found")
      return
    }
    for entry in keys {
      if verbose {
        print("Name: \(entry.info.name)")
        print("  ID: \(entry.info.id)")
        print("  Algorithm: \(entry.info.algorithm.rawValue)")
        print("  Auth: \(entry.info.auth.rawValue)")
        print("  Fingerprint: \(try SecureEnclaveKeys.fingerprint(keyName: entry.info.name))")
        print("")
      } else {
        print("\(entry.info.name) (\(entry.info.algorithm.rawValue))")
      }
    }
  }
}
