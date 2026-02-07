import Foundation
import Security

extension Data {
  /// Lowercase hex string representation of the data bytes.
  public var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}

#if !os(Linux) && !os(Windows)
  /// Create a SecAccessControl with the given flags, throwing on failure.
  public func makeAccessControl(
    flags: SecAccessControlCreateFlags
  ) throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    let access = unsafe SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      flags,
      &error
    )
    if let err = error {
      throw err.takeRetainedValue() as Swift.Error
    }
    return access!
  }
#endif
