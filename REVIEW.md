# Principal Engineer Review: Mac N Keys

## Execution Summary

The `mac-n-keys` tool is a promising unification of macOS security primitives, successfully bridging the gap between SSH, AGE, and Apple Passwords. The architecture leveraging `PasswordManagerBrowserExtensionHelper` via Native Messaging is clever and avoids fragile UI scripting.

However, there are critical documentation inconsistencies, security/privacy leaks in the CLI interaction, and UX rough edges that need addressing before a stable release.

## 1. Critical Issues (Must Fix)

### 1.1. Documentation vs. Implementation Mismatch
The `README.md` describes a **UDP** architecture with a `--port` flag, but the implementation uses **Unix Domain Sockets** and a `--socket` flag.
- **Impact**: Users following the README will fail to start the daemon or authenticate.
- **Fix**: Update `README.md` to reflect the UDS architecture.
- **Ref**: `Sources/Lib/Transport/DaemonConnection.swift` vs `README.md`.

### 1.2. Insecure PIN Entry
`mac-n-keys passwords auth` uses `readLine()` to capture the 6-digit verification code.
- **Impact**: The code is echoed to the terminal, staying in the scrollback history. This is a privacy leak for the SRP verifier.
- **Fix**: Use `libc`'s `getpass` or a Swift wrapper to mask input.
- **Ref**: `Sources/MacNKeys/Commands/Passwords/PasswordsAuthCommand.swift:136`

### 1.3. Hybrid Identity Parsing Looseness
The hybrid AGE identity parsing falls back to P-256 if length checks fail, without validating if the data was *intended* to be hybrid.
- **Impact**: Corrupted hybrid keys might be silently loaded as invalid P-256 keys, leading to confusing downstream errors.
- **Fix**: Implement strict parsing. If the HRP is `AGE-PLUGIN-SE-` but the data structure doesn't match known schemas, fail hard.
- **Ref**: `Sources/Lib/AGE/Plugin.swift:602`

## 2. High Priority Improvements

### 2.1. "Fail-Late" Session Expiration
When a session expires (24h), `SessionKeychain.load` triggers a Touch ID prompt *before* checking the timestamp inside the encrypted blob.
- **Impact**: User approves biometric prompt only to receive "Session expired" error.
- **Fix**: Store a plaintext metadata item (e.g., `session-mw`) alongside the encrypted session containing the expiration time. Check this before prompting.
- **Ref**: `Sources/Lib/SessionKeychain.swift:65`

### 2.2. Process Tracing Heuristics
`ProcessTracer` relies on `getppid()`. For shell pipelines or wrappers (e.g., `make`, `npm run`), this shows the immediate parent (the runner) rather than the user-facing tool.
- **Recommendation**: Walk the process tree to find the first "interactive" or "known" application (like Terminal, VSCode, SSH Agent) if the direct parent is a generic shell/runner.

## 3. Code Quality & Maintenance

- **Unsafe usage**: The codebase uses `unsafe` keywords extensively. While necessary for C-interop, wrapping these in cleaner abstractions (as done in `ProcessTracer`) throughout would be better.
- **Testing**: Ensure `AGE` plugin protocol edge cases (e.g., broken stanzas, partial reads) are covered, as the state machine in `Plugin.swift` is complex.
