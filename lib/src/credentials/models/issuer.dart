class Issuer {
  final String id;

  Issuer({required this.id});

  factory Issuer.fromJson(dynamic json) {
    if (json is String) {
      return Issuer(id: json);
    } else if (json is Map<String, dynamic>) {
      final id = json['id'] as String;
      final propertiesMap = Map<String, dynamic>.from(json);
      propertiesMap.remove('id');
      return Issuer(id: id);
    } else {
      throw ArgumentError('Issuer must be a String or a Map');
    }
  }

  dynamic toJson() => id;

  factory Issuer.fromUri(String uri) => Issuer(id: uri);

  bool get isEmpty => id.isEmpty;

  @override
  String toString() => 'Issuer{id: $id}';
}
