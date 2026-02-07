import AppKit
import ArgumentParser
import BigInt
import Foundation
import Lib

struct PasswordsGetCommand: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "get",
    abstract: "Get password for a URL (requires Touch ID)"
  )

  @Argument(help: "URL to look up")
  var url: String

  @Option(help: "Username filter")
  var username: String?

  @Flag(name: .shortAndLong, help: "Copy password to clipboard (cleared after 30s)")
  var clipboard = false

  func run() async throws {
    let decrypted = try sendPasswordsRequest(forDomain: url) { session in
      try PasswordsMessages.getPasswordForURL(
        session: session, url: url, loginName: username ?? "")
    }
    if let entries = decrypted["Entries"] as? [[String: Any]] {
      for entry in entries {
        if let usr = entry["USR"] as? String {
          print("Username: \(usr)")
        }
        if let pwd = entry["PWD"] as? String {
          if clipboard {
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            pasteboard.setString(pwd, forType: .string)
            print("Password copied to clipboard (will clear in 30s)")
            // Schedule clipboard clear after 30 seconds
            DispatchQueue.global().asyncAfter(deadline: .now() + 30) {
              let current = NSPasteboard.general.string(forType: .string)
              if current == pwd {
                NSPasteboard.general.clearContents()
              }
            }
            // Wait for the clear timer
            try await Task.sleep(for: .seconds(30))
          } else {
            print("Password: \(pwd)")
          }
        }
        if !clipboard {
          print("")
        }
      }
    } else {
      print("No results found")
    }
  }
}
