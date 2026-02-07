#if os(Linux)
  @preconcurrency import Foundation
#else
  import Foundation
#endif

/// Abstraction of a line-based communication stream
public protocol AGEStream {
  func readLine() throws -> String?
  func writeLine(_: String) throws
}

public class StandardIOStream: AGEStream {
  public init() {}

  public func readLine() throws -> String? {
    return Swift.readLine(strippingNewline: true)
  }

  public func writeLine(_ line: String) throws {
    FileHandle.standardOutput.write(Data(line.utf8))
    FileHandle.standardOutput.write(Data([0xa]))
    fflush(stdout)
  }
}
