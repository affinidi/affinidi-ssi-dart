import 'dart:collection';

import '../../../../util/json_util.dart';

abstract interface class _CredentialStatusV2Interface
    extends UnmodifiableMapBase<String, dynamic> {
  Uri? get id;
  String? get type;

  /// Converts this status to a JSON-serializable map.
  Map<String, dynamic> toJson() {
    return cleanEmpty({
      'id': id?.toString(),
      'type': type,
      ...Map<String, dynamic>.fromEntries(entries)
    });
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
  final Map<String, dynamic> _revocationFields;

  /// The URL identifier for this status information.
  @override
  Uri? id;

  /// The type of status mechanism used.
  @override
  String? type;

  /// Creates a [MutableCredentialStatusV2] instance.
  ///
  /// The [revocationFields] contains status-related fields, including 'id', 'type', and others.
  /// The 'id' is validated and converted to a [Uri] using [getUri], and 'type' is validated
  /// as a [String] using [getString].
  MutableCredentialStatusV2(Map<String, dynamic>? revocationFields)
      : id = getUri(revocationFields ?? {}, 'id'),
        type = getString(revocationFields ?? {}, 'type'),
        _revocationFields = UnmodifiableMapView(
            Map<String, dynamic>.from(revocationFields ?? {})
              ..remove('id')
              ..remove('type'));

  /// Creates a [MutableCredentialStatusV2] from JSON data.
  factory MutableCredentialStatusV2.fromJson(Map<String, dynamic> json) {
    return MutableCredentialStatusV2(json);
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
interface class CredentialStatusV2 extends _CredentialStatusV2Interface {
  /// The optional URL identifier for the credential status object (VCDM v2.0).
  @override
  final Uri? id;

  /// The type of status mechanism used.
  ///
  /// This is required and expresses the credential status type.
  @override
  final String type;

  /// Revocation-related fields stored as an unmodifiable map.
  final UnmodifiableMapView<String, dynamic> _revocationFields;

  /// Creates a [CredentialStatusV2] instance.
  ///
  /// The [revocationFields] contains status-related fields, including 'id', 'type', and others.
  /// The 'id' is validated as a [Uri] using [getUri], and 'type' is required and validated
  /// using [getMandatoryString]. Other fields are stored in an unmodifiable map.
  CredentialStatusV2(Map<String, dynamic> revocationFields)
      : id = getUri(revocationFields, 'id'),
        type = getMandatoryString(revocationFields, 'type'),
        _revocationFields =
            UnmodifiableMapView(Map<String, dynamic>.from(revocationFields)
              ..remove('id')
              ..remove('type'));

  /// Creates a [CredentialStatusV2] from JSON data.
  factory CredentialStatusV2.fromJson(Map<String, dynamic> json) {
    return CredentialStatusV2(json);
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
