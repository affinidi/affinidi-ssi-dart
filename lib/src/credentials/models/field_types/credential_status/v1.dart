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
  /// The URL of optional unique identifier for the credential status object.
  @override
  Uri? get id => getUri(_revocationFields, 'id');

  /// The schema type of credential status.
  @override
  String? get type => getString(_revocationFields, 'type');

  /// Revocation-related fields stored as a generic map.
  final Map<String, dynamic> _revocationFields;

  /// Creates a [MutableCredentialStatusV1] instance.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  /// The [revocationFields] contains optional revocation-related fields to be included in JSON.
  MutableCredentialStatusV1(
    Map<String, dynamic>? revocationFields,
  ) : _revocationFields = revocationFields ?? {};

  /// Creates a [MutableCredentialStatusV1] from JSON data.
  factory MutableCredentialStatusV1.fromJson(Map<String, dynamic> json) {
    final fieldsMap = Map<String, dynamic>.from(json);
    return MutableCredentialStatusV1(fieldsMap);
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
      value = Uri.parse(value as String);
    }
    _revocationFields[key] = value;
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
  /// The URL of optional unique identifier for the credential status object.
  @override
  Uri get id => getMandatoryUri(_revocationFields, 'id');

  /// The schema type of credential status.
  @override
  String get type => getMandatoryString(_revocationFields, 'type');

  final UnmodifiableMapView<String, dynamic> _revocationFields;

  CredentialStatusV1._(
    UnmodifiableMapView<String, dynamic> revocationFields,
  ) : _revocationFields = revocationFields;

  /// Creates a [CredentialStatusV1] from JSON data.
  factory CredentialStatusV1.fromJson(Map<String, dynamic> json) {
    final fieldsMap = UnmodifiableMapView<String, dynamic>(json);
    return CredentialStatusV1._(fieldsMap);
  }

  @override
  dynamic operator [](Object? key) {
    if (key == 'id') {
      return id;
    }
    if (key == 'type') {
      return type;
    }
    return _revocationFields[key];
  }

  @override
  Iterable<String> get keys => _revocationFields.keys;
}
