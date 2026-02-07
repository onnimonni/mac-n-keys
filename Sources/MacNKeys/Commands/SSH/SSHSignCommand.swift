import ArgumentParser
import Foundation
import Lib

struct SSHSignCommand: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "sign",
    abstract: "Sign data from stdin (requires Touch ID)"
  )

  @Argument(help: "Key name")
  var name: String

  @Flag(help: "Output hex instead of raw bytes")
  var hex = false

  func run() throws {
    let inputData = FileHandle.standardInput.readDataToEndOfFile()
    guard !inputData.isEmpty else {
      throw SSHError.noInputData
    }
    let signature = try SecureEnclaveKeys.sign(keyName: name, data: inputData)
    if hex {
      print(signature.hexString)
    } else {
      FileHandle.standardOutput.write(signature)
    }
  }
}
