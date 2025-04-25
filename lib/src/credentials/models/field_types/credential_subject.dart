import 'dart:collection';

import 'package:ssi/src/util/json_util.dart';

abstract interface class CredentialSubject
    extends UnmodifiableMapBase<String, dynamic> {
  Uri? get id;

  Map<String, dynamic> toJson() {
    return Map<String, dynamic>.fromEntries(entries);
  }
}

class MutableCredentialSubject extends CredentialSubject {
  @override
  Uri? get id => getUri(_claims, 'id');

  Map<String, dynamic> _claims;

  MutableCredentialSubject(
    Map<String, dynamic>? claims,
  ) : _claims = claims ?? {};

  @override
  operator [](Object? key) {
    if (key == 'id') {
      return id;
    }

    return _claims[key];
  }

  @override
  void operator []=(String key, value) {
    if (key == 'id') {
      value = Uri.parse(value);
    }

    _claims[key] = value;
  }

  @override
  void clear() => _claims.clear();

  @override
  Iterable<String> get keys => _claims.keys;

  @override
  remove(Object? key) => _claims.remove(key);
}

class ParsedCredentialSubject extends CredentialSubject {
  @override
  Uri? get id => getUri(_claims, 'id');

  Map<String, dynamic> _claims;

  ParsedCredentialSubject._(
    Map<String, dynamic>? claims,
  ) : _claims = claims ?? {};

  factory ParsedCredentialSubject.fromJson(Map<String, dynamic> json) {
    final claimsMap = Map<String, dynamic>.from(json);
    return ParsedCredentialSubject._(claimsMap);
  }

  @override
  @override
  operator [](Object? key) {
    if (key == 'id') {
      return id;
    }

    return _claims[key];
  }

  @override
  Iterable<String> get keys => _claims.keys;
}
