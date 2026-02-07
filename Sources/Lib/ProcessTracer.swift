import Foundation

import LocalAuthentication

#if canImport(Darwin)
  import Darwin

  // from libproc.h
  @_silgen_name("proc_pidpath")
  @discardableResult func proc_pidpath(
    _ pid: Int32, _ buffer: UnsafeMutableRawPointer!, _ buffersize: UInt32
  ) -> Int32

  /// Traces parent process chain to identify the calling application.
  ///
  /// SECURITY NOTE (TOCTOU): Process information from sysctl/proc_pidpath is
  /// inherently racy — a process can change its argv or exec a different binary
  /// between inspection and use. This data is advisory (for Touch ID prompts)
  /// and must not be used for access control decisions.
  public enum ProcessTracer {

    public struct ProcessInfo: Sendable {
      public let pid: Int32
      public let name: String
      public let path: String
      public let parentPID: Int32?
    }

    /// Get info about a process by PID.
    public static func processInfo(for pid: Int32) -> ProcessInfo {
      let pathPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
      defer { pathPointer.deallocate() }
      _ = unsafe proc_pidpath(pid, pathPointer, UInt32(MAXPATHLEN))
      let path = unsafe String(cString: pathPointer)

      var len = unsafe MemoryLayout<kinfo_proc>.size
      let infoPointer = UnsafeMutableRawPointer.allocate(byteCount: len, alignment: 1)
      defer { infoPointer.deallocate() }
      var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
      unsafe sysctl(&name, UInt32(name.count), infoPointer, &len, nil, 0)
      let info = unsafe infoPointer.load(as: kinfo_proc.self)
      let ppid = unsafe info.kp_eproc.e_ppid
      var mutableInfo = info
      let procName = unsafe withUnsafeMutablePointer(to: &mutableInfo.kp_proc.p_comm.0) {
        pointer in
        unsafe String(cString: pointer)
      }

      return ProcessInfo(
        pid: pid,
        name: procName,
        path: path,
        parentPID: ppid != 0 ? ppid : nil
      )
    }

    /// Walk parent chain from a PID up to init.
    public static func processChain(from pid: Int32) -> [ProcessInfo] {
      var chain: [ProcessInfo] = []
      var current = pid
      var seen = Set<Int32>()
      while !seen.contains(current) {
        seen.insert(current)
        let info = processInfo(for: current)
        chain.append(info)
        guard let parent = info.parentPID else { break }
        current = parent
      }
      return chain
    }

    /// Get a human-readable description of the calling process (parent of current).
    public static func callerDescription() -> String {
      let ppid = getppid()
      let info = processInfo(for: ppid)
      let name = info.path.isEmpty ? info.name : URL(fileURLWithPath: info.path).lastPathComponent
      return "\(name) (pid \(ppid))"
    }

    /// Get the immediate parent process info.
    public static func parentProcess() -> ProcessInfo {
      processInfo(for: getppid())
    }

    /// Create an LAContext pre-configured with caller description for Touch ID prompts.
    public static func makeAuthContext(reason: String) -> LAContext {
      let ctx = LAContext()
      ctx.localizedReason = "\(reason) requested by \(callerDescription())"
      ctx.localizedCancelTitle = "Deny"
      return ctx
    }
  }

#else
  /// Stub for non-Darwin platforms.
  public enum ProcessTracer {
    public struct ProcessInfo: Sendable {
      public let pid: Int32
      public let name: String
      public let path: String
      public let parentPID: Int32?
    }

    public static func callerDescription() -> String {
      "unknown"
    }

    public static func parentProcess() -> ProcessInfo {
      ProcessInfo(pid: 0, name: "unknown", path: "", parentPID: nil)
    }

    public static func processInfo(for pid: Int32) -> ProcessInfo {
      ProcessInfo(pid: pid, name: "unknown", path: "", parentPID: nil)
    }

    public static func processChain(from pid: Int32) -> [ProcessInfo] {
      [processInfo(for: pid)]
    }

    public static func makeAuthContext(reason: String) -> LAContext {
      let ctx = LAContext()
      ctx.localizedReason = reason
      ctx.localizedCancelTitle = "Deny"
      return ctx
    }
  }
#endif
