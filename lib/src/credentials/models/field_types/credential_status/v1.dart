import 'dart:collection';

import '../../../../util/json_util.dart';

abstract interface class _CredentialStatusV1Interface
    extends UnmodifiableMapBase<String, dynamic> {
  Uri? get id;
  String? get type;

  /// Converts this status to a JSON-serializable map.
  Map<String, dynamic> toJson() {
    return cleanEmpty(Map<String, dynamic>.fromEntries(entries.map((e) =>
        MapEntry(e.key, e.key == 'id' ? e.value?.toString() : e.value))));
  }
}

/// Represents a Mutable Credential Status for verifiable credentials following W3C standards.
///
/// This specification defines the credentialStatus property for discovering information related
/// to the status of a verifiable credential, such as whether it is revoked or not.
/// It uses JSON Schema format to check status of credential.
///
/// Example:
/// ```dart
/// final credentialStatus = MutableCredentialStatusV1({
///   'id': Uri.parse('test-credential-status-id'),
///   'type': 'BitstringStatusListEntry',
///   'revocationListIndex': '94567',
///   'revocationListCredential': 'https://pharma.example.com/credentials/status/3',
/// });
/// ```
class MutableCredentialStatusV1 extends _CredentialStatusV1Interface {
  final Map<String, dynamic> _revocationFields;

  /// The URL of optional unique identifier for the credential status object.
  @override
  Uri? id;

  /// The schema type of credential status.
  @override
  String? type;

  /// Creates a [MutableCredentialStatusV1] instance.
  ///
  /// The [revocationFields] contains status-related fields, including 'id', 'type', and others.
  /// The 'id' is validated and converted to a [Uri] using [getUri], and 'type' is validated
  /// as a [String] using [getString].
  MutableCredentialStatusV1(Map<String, dynamic>? revocationFields)
      : id = getUri(revocationFields ?? {}, 'id'),
        type = getString(revocationFields ?? {}, 'type'),
        _revocationFields = UnmodifiableMapView(
            Map<String, dynamic>.from(revocationFields ?? {})
              ..remove('id')
              ..remove('type'));

  /// Creates a [MutableCredentialStatusV1] from JSON data.
  factory MutableCredentialStatusV1.fromJson(Map<String, dynamic> json) {
    return MutableCredentialStatusV1(json);
  }

  @override
  dynamic operator [](Object? key) {
    if (key == 'id') return id;
    if (key == 'type') return type;
    return _revocationFields[key];
  }

  @override
  void operator []=(String key, dynamic value) {
    if (key == 'id') {
      id = getUri({'id': value}, 'id');
    } else if (key == 'type') {
      type = getString({'type': value}, 'type');
    } else {
      _revocationFields[key] = value;
    }
  }

  @override
  void clear() => _revocationFields.clear();

  @override
  Iterable<String> get keys => _revocationFields.keys;

  @override
  dynamic remove(Object? key) => _revocationFields.remove(key);
}

/// Represents a Credential Status for verifiable credentials following W3C standards.
///
/// This specification defines the credentialStatus property for discovering information related
/// to the status of a verifiable credential, such as whether it is revoked or not.
/// It uses JSON Schema format to check status of credential.
///
/// Example:
/// ```dart
/// final credentialStatus = CredentialStatusV1.fromJson({
///   'id': Uri.parse('test-credential-status-id'),
///   'type': 'BitstringStatusListEntry',
///   'revocationListIndex': '94567',
///   'revocationListCredential': 'https://pharma.example.com/credentials/status/3',
/// });
/// ```
class CredentialStatusV1 extends _CredentialStatusV1Interface {
  /// The URL of unique identifier for the credential status object.
  @override
  final Uri id;

  /// The schema type of credential status.
  @override
  final String type;

  /// Revocation-related fields stored as an unmodifiable map.
  final UnmodifiableMapView<String, dynamic> _revocationFields;

  /// Creates a [CredentialStatusV1] instance.
  ///
  /// The [revocationFields] contains status-related fields, including 'id', 'type', and others.
  /// The 'id' is required and validated as a [Uri] using [getMandatoryUri], and 'type' is
  /// required and validated using [getMandatoryString]. Other fields are stored in an unmodifiable map.
  CredentialStatusV1(Map<String, dynamic> revocationFields)
      : id = getMandatoryUri(revocationFields, 'id'),
        type = getMandatoryString(revocationFields, 'type'),
        _revocationFields =
            UnmodifiableMapView(Map<String, dynamic>.from(revocationFields)
              ..remove('id')
              ..remove('type'));

  /// Creates a [CredentialStatusV1] from JSON data.
  /// Throws an exception if 'id' or 'type' is missing or invalid.
  factory CredentialStatusV1.fromJson(Map<String, dynamic> json) {
    return CredentialStatusV1(json);
  }

  @override
  dynamic operator [](Object? key) {
    if (key == 'id') return id;
    if (key == 'type') return type;
    return _revocationFields[key];
  }

  @override
  Iterable<String> get keys => _revocationFields.keys;
}
