import Foundation
import XCTest

@testable import Lib

/// Verifies the apple-secrets → mac-n-keys rename is consistent across all
/// identifiers that end up in Keychain, filesystem, or dispatch labels.
final class NamingConsistencyTests: XCTestCase {

  // MARK: - Socket path uses mac-n-keys

  func testDefaultSocketPath_UsesMacNKeys() {
    let path = DaemonConnection.defaultSocketPath
    XCTAssertTrue(path.contains("mac-n-keys"), "Socket path must contain 'mac-n-keys'")
    XCTAssertFalse(path.contains("apple-secrets"), "Socket path must not contain 'apple-secrets'")
  }

  // MARK: - No old name leaks in error descriptions

  func testTransportErrors_NoOldName() {
    let errors: [TransportError] = [
      .helperNotFound,
      .helperCommunicationFailed,
      .helperPathUntrusted("/test"),
      .invalidResponse,
    ]
    for err in errors {
      let desc = err.localizedDescription
      XCTAssertFalse(desc.contains("apple-secrets"),
        "TransportError should not reference old name: \(desc)")
    }
  }

  func testUnixSocketErrors_NoOldName() {
    let errors: [UnixSocketError] = [
      .socketCreationFailed(0),
      .bindFailed(0),
      .listenFailed(0),
      .connectFailed(0),
      .pathTooLong,
      .alreadyRunning,
      .communicationFailed,
    ]
    for err in errors {
      let desc = err.localizedDescription
      XCTAssertFalse(desc.contains("apple-secrets"),
        "UnixSocketError should not reference old name: \(desc)")
    }
  }

  func testSessionKeychainErrors_NoOldName() {
    let errors: [SessionKeychainError] = [
      .saveFailed(0),
      .loadFailed(0),
      .deleteFailed(0),
      .sessionExpired,
    ]
    for err in errors {
      let desc = err.localizedDescription
      XCTAssertFalse(desc.contains("apple-secrets"),
        "SessionKeychainError should not reference old name: \(desc)")
    }
  }

  func testSSHErrors_NoOldName() {
    let errors: [SSHError] = [
      .keyNotFound("test"),
      .keychainError(0),
      .unsupportedAlgorithm,
      .noInputData,
      .duplicateKey("test"),
    ]
    for err in errors {
      let desc = err.localizedDescription
      XCTAssertFalse(desc.contains("apple-secrets"),
        "SSHError should not reference old name: \(desc)")
    }
  }

  func testSRPErrors_NoOldName() {
    let errors: [SRPError] = [
      .invalidServerPublicKey,
      .missingServerPublicKey,
      .missingSalt,
      .missingSharedKey,
      .randomGenerationFailed,
    ]
    for err in errors {
      let desc = err.localizedDescription
      XCTAssertFalse(desc.contains("apple-secrets"),
        "SRPError should not reference old name: \(desc)")
    }
  }
}
