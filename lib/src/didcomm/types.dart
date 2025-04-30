enum DidcommMessageTyp {
  plain,
  signed,
  encrypted;

  static const Map<DidcommMessageTyp, String> stringValues = {
    DidcommMessageTyp.plain: 'application/didcomm-plain+json',
    DidcommMessageTyp.signed: 'application/didcomm-signed+json',
    DidcommMessageTyp.encrypted: 'application/didcomm-encrypted+json'
  };
  String get value => stringValues[this]!;
}

enum AcknowledgeStatus {
  ok,
  fail,
  pending;

  static const Map<AcknowledgeStatus, String> stringValues = {
    AcknowledgeStatus.ok: 'OK',
    AcknowledgeStatus.pending: 'PENDING',
    AcknowledgeStatus.fail: 'FAIL'
  };
  String get value => stringValues[this]!;
}

enum ReturnRouteValue {
  none,
  all,
  thread;

  static const Map<ReturnRouteValue, String> stringValues = {
    ReturnRouteValue.none: 'none',
    ReturnRouteValue.all: 'all',
    ReturnRouteValue.thread: 'thread'
  };
  String get value => stringValues[this]!;
}

/// Combination of Key-Wrap and Key agreement algorithm
enum KeyWrapAlgorithm {
  ecdhES,
  ecdh1PU;

  static const Map<KeyWrapAlgorithm, String> stringValues = {
    KeyWrapAlgorithm.ecdhES: 'ECDH-ES+A256KW',
    KeyWrapAlgorithm.ecdh1PU: 'ECDH-1PU+A256KW',
  };
  String get value => stringValues[this]!;
}

enum EncryptionAlgorithm {
  a256cbc,
  a256gcm;

  static const Map<EncryptionAlgorithm, String> stringValues = {
    EncryptionAlgorithm.a256cbc: 'A256CBC-HS512',
    EncryptionAlgorithm.a256gcm: 'A256GCM',
  };
  String get value => stringValues[this]!;
}
