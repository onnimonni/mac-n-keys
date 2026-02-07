import ArgumentParser
import BigInt
import Foundation
import Lib

struct PasswordsOTPCommand: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "otp",
    abstract: "Get TOTP code for a URL (requires Touch ID)"
  )

  @Argument(help: "URL/domain to look up")
  var url: String

  func run() async throws {
    let normalizedURL = url.contains("://") ? url : "https://\(url)"
    let decrypted = try sendPasswordsRequest(forDomain: url) { session in
      try PasswordsMessages.getOTPForURL(session: session, url: normalizedURL)
    }
    if let entries = decrypted["Entries"] as? [[String: Any]] {
      for entry in entries {
        if let code = entry["code"] as? String {
          print(code)
        }
      }
    } else {
      print("No OTP found")
    }
  }
}
