import Foundation

/// Protocol constants ported from apw/src/const.ts.
public enum PasswordsCommand: Int {
  case end = 0
  case handshake = 2
  case getLoginNamesForURL = 4
  case getPasswordForLoginName = 5
  case getCapabilities = 14
  case getOneTimeCodes = 16
  case didFillOneTimeCode = 17
}

public enum MSGType: Int {
  case clientKeyExchange = 0
  case serverKeyExchange = 1
  case clientVerification = 2
  case serverVerification = 3
}

public enum PasswordsAction: Int {
  case search = 2
  case ghostSearch = 5
}

/// Protocol message constructors ported from apw/src/client.ts.
public enum PasswordsMessages {

  private static let browserName = "Arc"
  private static let version = "1.0"
  private static let srpProtocol = 1  // SRP_WITH_RFC_VERIFICATION

  public static func getCapabilities() -> [String: Any] {
    ["cmd": PasswordsCommand.getCapabilities.rawValue]
  }

  public static func requestChallenge(session: SRPSession) throws -> [String: Any] {
    let pake: [String: Any] = [
      "TID": session.username,
      "MSG": MSGType.clientKeyExchange.rawValue,
      "A": session.serialize(session.bigUIntToData(session.clientPublicKey)),
      "VER": version,
      "PROTO": [srpProtocol],
    ]
    let pakeJSON = try JSONSerialization.data(withJSONObject: pake)
    let pakeBase64 = pakeJSON.base64EncodedString()

    return [
      "cmd": PasswordsCommand.handshake.rawValue,
      "msg": [
        "QID": "m0",
        "PAKE": pakeBase64,
        "HSTBRSR": browserName,
      ] as [String: Any],
    ]
  }

  public static func verifyChallenge(session: SRPSession, m: Data) throws -> [String: Any] {
    let pake: [String: Any] = [
      "TID": session.username,
      "MSG": MSGType.clientVerification.rawValue,
      "M": session.serialize(m, prefix: false),
    ]
    let pakeJSON = try JSONSerialization.data(withJSONObject: pake)
    let pakeBase64 = pakeJSON.base64EncodedString()

    return [
      "cmd": PasswordsCommand.handshake.rawValue,
      "msg": [
        "HSTBRSR": browserName,
        "QID": "m2",
        "PAKE": pakeBase64,
      ] as [String: Any],
    ]
  }

  public static func getLoginNamesForURL(session: SRPSession, url: String) throws -> [String: Any]
  {
    let payload: [String: Any] = [
      "ACT": PasswordsAction.ghostSearch.rawValue,
      "URL": url,
    ]
    return [
      "cmd": PasswordsCommand.getLoginNamesForURL.rawValue,
      "tabId": 1,
      "frameId": 1,
      "url": url,
      "payload": try encryptedPayloadString(
        session: session, qid: "CmdGetLoginNames4URL", payload: payload),
    ]
  }

  public static func getPasswordForURL(
    session: SRPSession, url: String, loginName: String
  ) throws -> [String: Any] {
    let payload: [String: Any] = [
      "ACT": PasswordsAction.search.rawValue,
      "URL": url,
      "USR": loginName,
    ]
    return [
      "cmd": PasswordsCommand.getPasswordForLoginName.rawValue,
      "tabId": 0,
      "frameId": 0,
      "url": url,
      "payload": try encryptedPayloadString(
        session: session, qid: "CmdGetPassword4LoginName", payload: payload),
    ]
  }

  public static func getOTPForURL(session: SRPSession, url: String) throws -> [String: Any] {
    let payload: [String: Any] = [
      "ACT": PasswordsAction.search.rawValue,
      "TYPE": "oneTimeCodes",
      "frameURLs": [url],
    ]
    return [
      "cmd": PasswordsCommand.didFillOneTimeCode.rawValue,
      "tabId": 0,
      "frameId": 0,
      "payload": try encryptedPayloadString(
        session: session, qid: "CmdDidFillOneTimeCode", payload: payload),
    ]
  }

  /// Encrypt payload, serialize, wrap in SMSG envelope, and return as JSON string.
  private static func encryptedPayloadString(
    session: SRPSession, qid: String, payload: [String: Any]
  ) throws -> String {
    let encrypted = try session.encrypt(payload)
    let smsg: [String: Any] = [
      "TID": session.username,
      "SDATA": session.serialize(encrypted),
    ]
    return try jsonString(["QID": qid, "SMSG": smsg] as [String: Any])
  }

  private static func jsonString(_ obj: Any) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: obj)
    guard let str = String(data: data, encoding: .utf8) else {
      throw TransportError.invalidResponse
    }
    return str
  }
}
