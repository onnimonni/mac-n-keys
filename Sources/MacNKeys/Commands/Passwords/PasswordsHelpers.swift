import BigInt
import Foundation
import Lib

/// Load a saved session from Keychain, restoring the SRP session state.
func loadSession(forDomain domain: String? = nil) throws -> (session: SRPSession, socketPath: String) {
  let saved = try SessionKeychain.load(forDomain: domain)
  let session = SRPSession.restore(
    username: saved.username, sharedKey: BigUInt(saved.sharedKey), useBase64: true)
  return (session: session, socketPath: saved.socketPath)
}

/// Send an encrypted Passwords request and decrypt the response.
/// The `buildMessage` closure receives the loaded session so it can encrypt the payload.
func sendPasswordsRequest(
  forDomain url: String,
  buildMessage: (SRPSession) throws -> [String: Any]
) throws -> [String: Any] {
  let (session, socketPath) = try loadSession(forDomain: url)
  let msg = try buildMessage(session)
  let resp = try DaemonConnection.sendMessage(msg, socketPath: socketPath)
  guard let payload = resp["payload"] as? [String: Any] else {
    throw TransportError.invalidResponse
  }
  return try decryptPayload(payload, session: session)
}

/// Decrypt a payload from the Passwords helper.
func decryptPayload(_ payload: [String: Any], session: SRPSession) throws -> [String: Any] {
  guard let smsgRaw = payload["SMSG"] else {
    throw TransportError.invalidResponse
  }
  let smsg: [String: Any]
  if let str = smsgRaw as? String, let data = str.data(using: .utf8),
    let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
  {
    smsg = parsed
  } else if let dict = smsgRaw as? [String: Any] {
    smsg = dict
  } else {
    throw TransportError.invalidResponse
  }

  guard let tid = smsg["TID"] as? String, tid == session.username,
    let sdata = smsg["SDATA"] as? String
  else {
    throw TransportError.invalidResponse
  }

  let encryptedData = session.deserialize(sdata)
  let decryptedData = try session.decrypt(encryptedData)
  guard
    let result = try? JSONSerialization.jsonObject(with: decryptedData) as? [String: Any]
  else {
    throw TransportError.invalidResponse
  }
  return result
}
