import ArgumentParser
import Lib

struct SSHPublicKeyCommand: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "public-key",
    abstract: "Show public key in SSH format"
  )

  @Argument(help: "Key name")
  var name: String

  @Flag(name: .shortAndLong, help: "Show fingerprint instead")
  var fingerprint = false

  func run() throws {
    if fingerprint {
      print(try SecureEnclaveKeys.fingerprint(keyName: name))
    } else {
      print(try SecureEnclaveKeys.publicKeyString(keyName: name))
    }
  }
}
