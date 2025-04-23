import 'dart:collection';

class CredentialSubject extends MapBase<String, dynamic> {
  final String? id;
  final Map<String, dynamic> _claims;

  CredentialSubject({
    this.id,
    required Map<String, dynamic> claims,
  }) : _claims = claims;

  factory CredentialSubject.fromJson(Map<String, dynamic> json) {
    final id = json['id'] as String?;
    final claimsMap = Map<String, dynamic>.from(json);
    if (id != null) {
      claimsMap.remove('id');
    }
    return CredentialSubject(
      id: id,
      claims: claimsMap,
    );
  }

  Map<String, dynamic> toJson() {
    final json = Map<String, dynamic>.from(_claims);
    if (id != null) {
      json['id'] = id;
    }
    return json;
  }

  @override
  dynamic operator [](Object? key) => _claims[key];

  @override
  void operator []=(String key, dynamic value) {
    _claims[key] = value;
  }

  @override
  void clear() => _claims.clear();

  @override
  Iterable<String> get keys => _claims.keys;

  @override
  dynamic remove(Object? key) => _claims.remove(key);

  @override
  String toString() => 'CredentialSubject{id: $id, claims: $_claims}';
}
