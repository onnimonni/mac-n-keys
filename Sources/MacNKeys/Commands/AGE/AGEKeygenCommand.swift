import ArgumentParser
import Foundation
import Lib

struct AGEGroup: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "age",
    abstract: "Manage AGE keys in the Secure Enclave",
    subcommands: [
      AGEKeygenCommand.self,
      AGERecipientsCommand.self,
    ]
  )
}

struct AGEKeygenCommand: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "keygen",
    abstract: "Generate a new SE-bound AGE identity"
  )

  @Option(name: .shortAndLong, help: "Output file")
  var output: String?

  @Option(help: "Access control: none, any-biometry-or-passcode, current-biometry")
  var accessControl: String = "any-biometry-or-passcode"

  @Option(help: "Recipient type: se, tag")
  var recipientType: String = "se"

  @Flag(help: "Generate post-quantum keys")
  var pq = false

  func run() throws {
    let ac: AGEKeyAccessControl = switch accessControl {
    case "none": .none
    case "passcode": .passcode
    case "any-biometry": .anyBiometry
    case "any-biometry-or-passcode": .anyBiometryOrPasscode
    case "any-biometry-and-passcode": .anyBiometryAndPasscode
    case "current-biometry": .currentBiometry
    case "current-biometry-and-passcode": .currentBiometryAndPasscode
    default: throw ValidationError("Invalid access control: \(accessControl)")
    }
    let rt: AGERecipientType = switch recipientType {
    case "se": .se
    case "tag": .tag
    default: throw ValidationError("Invalid recipient type: \(recipientType)")
    }

    let plugin = AGEPlugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
    let result = try plugin.generateKey(accessControl: ac, recipientType: rt, now: Date(), pq: pq)

    if let outputFile = output {
      FileManager.default.createFile(
        atPath: outputFile,
        contents: Data(result.0.utf8),
        attributes: [.posixPermissions: 0o600]
      )
      print("Public key: \(result.1)")
    } else {
      print(result.0)
    }
  }
}
