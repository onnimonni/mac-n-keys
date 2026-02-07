import ArgumentParser
import BigInt
import Foundation
import Lib

struct PasswordsListCommand: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "list",
    abstract: "List accounts for a URL (requires Touch ID)"
  )

  @Argument(help: "URL to look up")
  var url: String

  func run() async throws {
    let decrypted = try sendPasswordsRequest(forDomain: url) { session in
      try PasswordsMessages.getLoginNamesForURL(session: session, url: url)
    }
    if let entries = decrypted["Entries"] as? [[String: Any]] {
      for entry in entries {
        if let usr = entry["USR"] as? String {
          print(usr)
        }
      }
    } else {
      print("No results found")
    }
  }
}
