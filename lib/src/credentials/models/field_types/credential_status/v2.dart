import 'dart:collection';

import '../../../../util/json_util.dart';

abstract interface class _CredentialStatusV2Interface
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
/// to the status of a verifiable credential, such as whether it is suspended or revoked.
///
/// Example:
/// ```dart
/// final credentialStatus = MutableCredentialStatusV2({
///   'id': Uri.parse('https://license.example/credentials/status/84#14278'),
///   'type': 'BitstringStatusListEntry',
///   'revocationListIndex': '94567',
///   'revocationListCredential': 'https://pharma.example.com/credentials/status/3',
/// });
/// ```
class MutableCredentialStatusV2 extends _CredentialStatusV2Interface {
  /// The URL identifier for this status information.
  @override
  Uri? get id => getUri(_revocationFields, 'id');

  /// The type of status mechanism used.
  @override
  String? get type => getMandatoryString(_revocationFields, 'type');

  /// Revocation-related fields stored as a generic map
  final Map<String, dynamic> _revocationFields;

  /// Creates a [MutableCredentialStatusV2]
  ///
  /// The [revocationFields] contains status-related fields, including 'id', 'type', and others.
  MutableCredentialStatusV2(
    Map<String, dynamic>? revocationFields,
  ) : _revocationFields = revocationFields ?? {};

  /// Creates a [MutableCredentialStatusV2] from JSON data.
  ///
  /// The [id] is the URL where status information can be found.
  /// The [type] identifies the status mechanism being used.
  /// The [revocationFields] contains optional revocation-related fields to be included in JSON.
  factory MutableCredentialStatusV2.fromJson(Map<String, dynamic> json) {
    final fieldsMap = Map<String, dynamic>.from(json);
    return MutableCredentialStatusV2(fieldsMap);
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
/// to the status of a verifiable credential, such as whether it is suspended or revoked.
///
/// Example:
/// ```dart
/// final credentialStatus = CredentialStatusV2(
///   id: Uri.parse('https://license.example/credentials/status/84#14278'),
///   type: 'BitstringStatusListEntry',
///   revocationFields: {'revocationListIndex': '94567', 'revocationListCredential': 'https://pharma.example.com/credentials/status/3'},
/// );
/// ```
class CredentialStatusV2 extends _CredentialStatusV2Interface {
  /// The URL of the schema including domain and filename.
  @override
  Uri? get id => getUri(_revocationFields, 'id');

  /// The schema type of validator used.
  ///
  /// Usually 'JsonSchemaValidator2018' for JSON Schema validation.
  @override
  String get type => getMandatoryString(_revocationFields, 'type');

  final UnmodifiableMapView<String, dynamic> _revocationFields;

  CredentialStatusV2._(
    UnmodifiableMapView<String, dynamic>? revocationFields,
  ) : _revocationFields =
            revocationFields ?? UnmodifiableMapView<String, dynamic>({});

  /// Creates a [CredentialStatusV2] from JSON data.
  factory CredentialStatusV2.fromJson(Map<String, dynamic> json) {
    final fieldsMap = UnmodifiableMapView<String, dynamic>(json);
    return CredentialStatusV2._(fieldsMap);
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
