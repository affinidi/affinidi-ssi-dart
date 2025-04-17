class CredentialSubject {
  final String? id;
  final Map<String, dynamic> claims;

  CredentialSubject({
    this.id,
    required this.claims,
  });

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
    final json = Map<String, dynamic>.from(claims);
    if (id != null) {
      json['id'] = id;
    }
    return json;
  }

  dynamic operator [](String key) => claims[key];
  bool containsKey(String key) => claims.containsKey(key);
  Iterable<String> get keys => claims.keys;
  Iterable<dynamic> get values => claims.values;
  Iterable<MapEntry<String, dynamic>> get entries => claims.entries;

  @override
  String toString() => 'CredentialSubject{id: $id, claims: $claims}';
}
