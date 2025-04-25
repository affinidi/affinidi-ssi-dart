import 'dart:collection';

import '../../../util/json_util.dart';

abstract interface class CredentialSubjectInterface
    extends UnmodifiableMapBase<String, dynamic> {
  Uri? get id;

  Map<String, dynamic> toJson() {
    return Map<String, dynamic>.fromEntries(entries);
  }
}

class MutableCredentialSubject extends CredentialSubjectInterface {
  @override
  Uri? get id => getUri(_claims, 'id');

  final Map<String, dynamic> _claims;

  MutableCredentialSubject(
    Map<String, dynamic>? claims,
  ) : _claims = claims ?? {};

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

class CredentialSubject extends CredentialSubjectInterface {
  @override
  Uri? get id => getUri(_claims, 'id');

  final UnmodifiableMapView<String, dynamic> _claims;

  CredentialSubject._(
    UnmodifiableMapView<String, dynamic>? claims,
  ) : _claims = claims ?? UnmodifiableMapView<String, dynamic>({});

  factory CredentialSubject.fromJson(Map<String, dynamic> json) {
    final claimsMap = UnmodifiableMapView<String, dynamic>(json);
    return CredentialSubject._(claimsMap);
  }

  @override
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
