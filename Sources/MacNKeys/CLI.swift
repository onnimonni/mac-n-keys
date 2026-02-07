import ArgumentParser
import Lib

@main
struct MacNKeys: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "mac-n-keys",
    abstract: "Unified macOS secrets management with Secure Enclave and Touch ID",
    subcommands: [
      SSHGroup.self,
      AGEGroup.self,
      PasswordsGroup.self,
      DaemonCommand.self,
    ]
  )
}
