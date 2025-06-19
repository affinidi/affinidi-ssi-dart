import 'dart:collection';

import '../../../util/json_util.dart';

abstract interface class _CredentialSubjectInterface
    extends UnmodifiableMapBase<String, dynamic> {
  Uri? get id;

  Map<String, dynamic> toJson() {
    return cleanEmpty(Map<String, dynamic>.fromEntries(entries.map((e) =>
        MapEntry(e.key, e.key == 'id' ? e.value?.toString() : e.value))));
  }
}

/// Represents a Mutable CredentialSubject for verifiable credentials following W3C standards.
///
/// A verifiable credential contains claims about one or more subjects.
/// This specification defines a credentialSubject property for the expression of claims about one or more subjects.
///
/// Example:
/// ```dart
/// final schema = MutableCredentialSubject(
///   id: Uri.parse('did:example:subjectV2'),
///   'email': 'user@test.com',
/// );
/// ```
class MutableCredentialSubject extends _CredentialSubjectInterface {
  @override
  Uri? get id => getUri(_claims, 'id');

  final Map<String, dynamic> _claims;

  /// Creates a [MutableCredentialSubject]
  ///
  /// The [claims]- is An assertion made about subject.
  MutableCredentialSubject(
    Map<String, dynamic>? claims,
  ) : _claims = claims ?? {};

  /// Creates a [MutableCredentialSubject] from JSON data.
  factory MutableCredentialSubject.fromJson(Map<String, dynamic> json) {
    final claimsMap = Map<String, dynamic>.from(json);
    return MutableCredentialSubject(claimsMap);
  }

  @override
  dynamic operator [](Object? key) {
    if (key == 'id') {
      return id;
    }

    return _claims[key];
  }

  @override
  void operator []=(String key, dynamic value) {
    if (key == 'id') {
      value = Uri.parse(value as String);
    }

    _claims[key] = value;
  }

  @override
  void clear() => _claims.clear();

  @override
  Iterable<String> get keys => _claims.keys;

  @override
  dynamic remove(Object? key) => _claims.remove(key);
}

/// Represents a CredentialSubject for verifiable credentials following W3C standards.
///
/// A verifiable credential contains claims about one or more subjects.
/// This specification defines a credentialSubject property for the expression of claims about one or more subjects.
///
/// Example:
/// ```dart
/// final subject = CredentialSubject(
///   id: Uri.parse('did:example:subjectV2'),
///   'email': 'user@test.com',
/// );
/// ```
class CredentialSubject extends _CredentialSubjectInterface {
  @override
  Uri? get id => getUri(_claims, 'id');

  final UnmodifiableMapView<String, dynamic> _claims;

  CredentialSubject._(
    UnmodifiableMapView<String, dynamic>? claims,
  ) : _claims = claims ?? UnmodifiableMapView<String, dynamic>({});

  /// Creates a [CredentialSubject] from JSON data.
  factory CredentialSubject.fromJson(Map<String, dynamic> json) {
    final claimsMap = UnmodifiableMapView<String, dynamic>(json);
    return CredentialSubject._(claimsMap);
  }

  @override
  dynamic operator [](Object? key) {
    if (key == 'id') {
      return id;
    }

    return _claims[key];
  }

  @override
  Iterable<String> get keys => _claims.keys;
}
