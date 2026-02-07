# Apple Secrets Implementation Plan

## Goal
Create a cohesive secrets management system for macOS that leverages Secure Enclave and Passwords.app, offering superior observability and security (Touch ID) compared to existing tools.

## Components

### 1. `swift-sudo-tid` (Better Sudo Integration)
A custom PAM module (or wrapper) to replace or augment `pam_tid.so`.
- **Feature**: Shows a Touch ID prompt with rich context: "sudo command 'rm -rf /' requested by user 'me'".
- **Implementation**:
    - Write a PAM module in Swift/Objective-C/C.
    - Use `LocalAuthentication` framework (`LAContext`) to trigger the prompt.
    - Retrieve the running command and user from the PAM context or process list.
    - Set `context.localizedReason` to the detailed command string.

### 2. `apple-secrets` CLI (Passwords.app Access)
A Swift native CLI tool to read/write secrets from iCloud Passwords (mimicking `apw`).
- **Feature**: Access Passwords.app secrets via the browser extension protocol (SRP handshake).
- **Security**: Enforce Touch ID per access.
- **Observability**: Show "Decrypting password for github.com" in the prompt.
- **Implementation**:
    - Port `apw`'s SRP handshake and protocol to Swift.
    - **Session Management**:
        - Perform the initial SRP handshake (requires 6-digit code).
        - Store the resulting **Session Key** in the macOS Keychain with `SecAccessControl` set to `.userPresence` (or `.biometryCurrentSet`) AND `kSecAttrLabel` = "iCloud Passwords Session".
    - **Access Flow**:
        - User runs `apple-secrets get https://github.com`.
        - Tool attempts to read the Session Key from Keychain.
        - **Critical Step**: Before accessing Keychain, or as part of the customized access, we ensure the prompt says "Accessing Github Password".
            - *Refinement*: `SecItemCopyMatching` on a `.userPresence` item triggers a standard prompt "Antigravity wants to access...".
            - To get custom text, we can use an `LAContext` object, set `localizedReason` to "Accessing password for github.com", evaluate it, and then pass it to `SecItemCopyMatching` via `kSecUseAuthenticationContext`. This binds the specific approval to the key retrieval.
        - Once Session Key is retrieved, use it to encrypt the request to the local iCloud Passwords daemon (UDP/WebSocket).
        - Decrypt response and output.

### 3. `age-plugin-se` (Enhanced AGE Integration)
Improve the existing `age-plugin-se` for better observability.
- **Feature**: Show "Decrypting content for <Parent Process>" instead of generic prompt.
- **Implementation**:
    - Modify `Crypto.swift` / `Plugin.swift` in `age-plugin-se`.
    - Detect the parent process name (e.g., `sops`, `age`, `scripts`) using `getppid()` and `proc_pidinfo`.
    - Instantiate a new `LAContext` for each decryption operation.
    - Set `context.localizedReason` to "Decrypting content for [Parent Process]".
    - Pass this context to the Secure Enclave signing/decryption calls.

### 4. `secretive` (SSH Integration)
- Continue using `Secretive` for SSH keys as it already provides excellent Secure Enclave integration.
- Optionally contribute "Parent Process" detection to `Secretive` if it lacks it (it currently shows "Access code signing key...", "Access SSH key...").

## Workflows

### Setup
1. `apple-secrets init`: Performs SRP handshake with iCloud Passwords. Stores session key in Keychain (Touch ID protected).
2. `age-plugin-se keygen`: Generates AGE Identity in Secure Enclave.

### Usage
- **Sudo**: `sudo ls` -> Pops up Touch ID "sudo ls requested...".
- **Get Secret**: `apple-secrets get github.com` -> Pops up Touch ID "Accessing github.com password...".
- **Decrypt**: `sops -d secrets.yaml` -> Pops up Touch ID "Decrypting for sops...".

## Task Breakdown

### Phase 1: Research & Prototyping
- [ ] **Sudo Observer**: Prototype a Swift binary that calls `LAContext` with custom reason. Verify if we can plug this into PAM or just wrap sudo. (PAM is cleaner but harder to deploy; a wrapper `suid` is easier but less standard).
    - *Decision*: A PAM module is the "correct" way. We can start with a simple PAM module in C that calls into a Swift framework or just Pure C/Obj-C.
- [ ] **apw-swift**: Prototype connecting to the local iCloud Passwords port (find port logic) and sending a "Hello" packet in Swift.

### Phase 2: Core Implementation
- [ ] Implement `apple-secrets` CLI with SRP and Keychain integration.
- [ ] Modify `age-plugin-se` to add parent process detection and custom `LAContext`.

### Phase 3: Integration
- [ ] Create a `sudo` integration (PAM module or instructions).
- [ ] Document full setup in `README.md`.
