import Foundation
import Lib

let version = "v0.3.0"

@main
struct AgePluginSECLI {
  static func main() {
    do {
      let plugin = AGEPlugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
      let options = try AgePluginOptions.parse(CommandLine.arguments)
      switch options.command {
      case .help:
        print(AgePluginOptions.help)
      case .version:
        print(version)
      case .keygen:
        let result = try plugin.generateKey(
          accessControl: options.accessControl,
          recipientType: options.recipientType, now: Date(),
          pq: options.pq)
        if let outputFile = options.output {
          FileManager.default.createFile(
            atPath: outputFile,
            contents: Data(result.0.utf8),
            attributes: [.posixPermissions: 0o600]
          )
          print("Public key: \(result.1)")
        } else {
          print(result.0)
        }
      case .recipients:
        var input = ""
        if let inputFile = options.input {
          input = try String(contentsOfFile: inputFile, encoding: .utf8)
        } else {
          guard let stdinData = try FileHandle.standardInput.readToEnd(),
            let stdinString = String(data: stdinData, encoding: .utf8)
          else {
            throw AgePluginOptions.Error.missingValue("stdin")
          }
          input = stdinString
        }
        let result = try plugin.generateRecipients(
          input: input, recipientType: options.recipientType)
        if let outputFile = options.output {
          FileManager.default.createFile(
            atPath: outputFile,
            contents: Data(result.utf8),
            attributes: [.posixPermissions: 0o600]
          )
        } else if result != "" {
          print(result)
        }
      case .plugin(let sm):
        switch sm {
        case .recipientV1:
          try plugin.runRecipientV1()
        case .identityV1:
          try plugin.runIdentityV1()
        }
      }
    } catch {
      print("\(CommandLine.arguments[0]): error: \(error.localizedDescription)")
      exit(-1)
    }
  }
}

/// Command-line options parser for the standalone age-plugin-se binary.
struct AgePluginOptions {
  enum Error: LocalizedError, Equatable {
    case unknownOption(String)
    case missingValue(String)
    case invalidValue(String, String)

    public var errorDescription: String? {
      switch self {
      case .unknownOption(let option): return "unknown option: `\(option)`"
      case .missingValue(let option): return "missing value for option `\(option)`"
      case .invalidValue(let option, let value):
        return "invalid value for option `\(option)`: `\(value)`"
      }
    }
  }

  enum StateMachine: String {
    case recipientV1 = "recipient-v1"
    case identityV1 = "identity-v1"
  }

  enum Command: Equatable {
    case help
    case version
    case keygen
    case recipients
    case plugin(StateMachine)
  }
  var command: Command

  var output: String?
  var input: String?

  var pq: Bool = false

  var accessControl = AGEKeyAccessControl.anyBiometryOrPasscode
  var recipientType = AGERecipientType.se

  static let help =
    """
    Usage:
      age-plugin-se keygen [--pq] [-o OUTPUT] [--access-control ACCESS_CONTROL] [--recipient-type RECIPIENT_TYPE]
      age-plugin-se recipients [--pq] [-o OUTPUT] [-i INPUT] [--recipient-type RECIPIENT_TYPE]

    Description:
      The `keygen` subcommand generates a new private key bound to the current
      Secure Enclave, with the given access controls, and outputs it to OUTPUT
      or standard output.

      The `recipients` subcommand reads an identity file from INPUT or standard
      input, and outputs the corresponding recipient(s) to OUTPUT or to standard
      output.

    Options:
      --access-control ACCESS_CONTROL   Access control for using the generated key.

                                        Supported values: none, passcode,
                                          any-biometry, any-biometry-and-passcode,
                                          any-biometry-or-passcode, current-biometry,
                                          current-biometry-and-passcode
                                        Default: any-biometry-or-passcode.

      -i, --input INPUT                 Read data from the file at path INPUT

      -o, --output OUTPUT               Write the result to the file at path OUTPUT

      --pq                              Generate post-quantum keys

      --recipient-type RECIPIENT_TYPE   Recipient type to generate.
                                        Supported values: se, tag.
                                        Default: se.

    Example:
      $ age-plugin-se keygen -o key.txt
      Public key: age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258
      $ tar cvz ~/data | age -r age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp > data.tar.gz.age
      $ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz
    """

  static func parse(_ args: [String]) throws -> AgePluginOptions {
    var opts = AgePluginOptions(command: .help)
    var i = 1
    while i < args.count {
      let arg = args[i]
      if arg == "keygen" {
        opts.command = .keygen
      } else if arg == "recipients" {
        opts.command = .recipients
      } else if ["--help", "-h"].contains(arg) {
        opts.command = .help
        break
      } else if ["--version"].contains(arg) {
        opts.command = .version
        break
      } else if ["--pq"].contains(arg) {
        opts.pq = true
      } else if [
        "--age-plugin", "-i", "--input", "-o", "--output", "--access-control",
        "--recipient-type",
      ].contains(where: {
        arg == $0 || arg.hasPrefix($0 + "=")
      }) {
        let argps = arg.split(separator: "=", maxSplits: 1)
        let value: String
        if argps.count == 1 {
          i += 1
          if i >= args.count {
            throw Error.missingValue(arg)
          }
          value = args[i]
        } else {
          value = String(argps[1])
        }
        let arg = String(argps[0])
        switch arg {
        case "--age-plugin":
          opts.command = try .plugin(
            StateMachine(rawValue: value) ?? { throw Error.invalidValue(arg, value) }())
        case "-i", "--input":
          opts.input = value
        case "-o", "--output":
          opts.output = value
        case "--access-control":
          opts.accessControl =
            try AGEKeyAccessControl(rawValue: value) ?? { throw Error.invalidValue(arg, value) }()
        case "--recipient-type":
          opts.recipientType =
            try AGERecipientType(rawValue: value) ?? { throw Error.invalidValue(arg, value) }()
        default:
          fatalError("unhandled option: \(arg)")
        }
      } else {
        throw Error.unknownOption(arg)
      }
      i += 1
    }
    return opts
  }
}
