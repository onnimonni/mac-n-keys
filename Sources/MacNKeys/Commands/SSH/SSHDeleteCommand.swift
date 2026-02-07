import ArgumentParser
import Foundation
import Lib

struct SSHDeleteCommand: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "delete",
    abstract: "Delete an SSH key"
  )

  @Argument(help: "Key name")
  var name: String

  @Flag(name: .shortAndLong, help: "Skip confirmation")
  var force = false

  func run() throws {
    if !force {
      print("Delete key '\(name)'? [y/N] ", terminator: "")
      fflush(stdout)
      guard let response = readLine()?.lowercased(),
        response == "y" || response == "yes"
      else {
        print("Aborted")
        return
      }
    }
    try SecureEnclaveKeys.delete(keyName: name, skipAuth: force)
    print("Deleted: \(name)")
  }
}
