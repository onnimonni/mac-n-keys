import ArgumentParser
import Foundation
import Lib

struct AGERecipientsCommand: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "recipients",
    abstract: "Extract recipients from an identity file"
  )

  @Option(name: .shortAndLong, help: "Input file")
  var input: String?

  @Option(name: .shortAndLong, help: "Output file")
  var output: String?

  @Option(help: "Recipient type: se, tag")
  var recipientType: String = "se"

  @Flag(help: "Output post-quantum recipients")
  var pq = false

  func run() throws {
    let rt: AGERecipientType = switch recipientType {
    case "se": .se
    case "tag": .tag
    default: throw ValidationError("Invalid recipient type: \(recipientType)")
    }

    var inputStr = ""
    if let inputFile = input {
      inputStr = try String(contentsOfFile: inputFile, encoding: .utf8)
    } else {
      inputStr = try String(data: FileHandle.standardInput.readToEnd()!, encoding: .utf8)!
    }

    let plugin = AGEPlugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
    let result = try plugin.generateRecipients(input: inputStr, recipientType: rt, pq: pq)

    if let outputFile = output {
      FileManager.default.createFile(
        atPath: outputFile,
        contents: Data(result.utf8),
        attributes: [.posixPermissions: 0o600]
      )
    } else if !result.isEmpty {
      print(result)
    }
  }
}
