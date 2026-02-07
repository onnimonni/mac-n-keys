import ArgumentParser
import Lib

struct SSHCreateCommand: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "create",
    abstract: "Create a new SSH key in the Secure Enclave"
  )

  @Argument(help: "Name for the key")
  var name: String

  @Option(help: "Algorithm: ecdsa256, mldsa65, mldsa87")
  var algorithm: String = "ecdsa256"

  @Option(help: "Auth requirement: presence, biometry, none")
  var auth: String = "presence"

  func run() throws {
    guard let algo = SecureEnclaveKeys.KeyAlgorithm(rawValue: algorithm) else {
      throw ValidationError("Invalid algorithm: \(algorithm)")
    }
    guard let authReq = SecureEnclaveKeys.AuthRequirement(rawValue: auth) else {
      throw ValidationError("Invalid auth: \(auth)")
    }

    // Check for duplicates
    if SecureEnclaveKeys.list().contains(where: { $0.info.name == name }) {
      throw SSHError.duplicateKey(name)
    }

    let result = try SecureEnclaveKeys.create(name: name, algorithm: algo, auth: authReq)
    print("Created key: \(result.info.name)")
    print("ID: \(result.info.id)")
    print("")
    print(try SecureEnclaveKeys.publicKeyString(keyName: name))
  }
}
