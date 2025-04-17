class Issuer {
  final String id;
  final Map<String, dynamic>? properties;

  Issuer({
    required this.id,
    this.properties,
  });

  factory Issuer.fromJson(dynamic json) {
    if (json is String) {
      return Issuer(id: json);
    } else if (json is Map<String, dynamic>) {
      final id = json['id'] as String;
      final propertiesMap = Map<String, dynamic>.from(json);
      propertiesMap.remove('id');
      return Issuer(
        id: id,
        properties: propertiesMap.isNotEmpty ? propertiesMap : null,
      );
    } else {
      throw ArgumentError('Issuer must be a String or a Map');
    }
  }

  dynamic toJson() {
    if (properties != null && properties!.isNotEmpty) {
      return {
        'id': id,
        ...properties!,
      };
    }
    return id;
  }

  factory Issuer.fromUri(String uri) => Issuer(id: uri);

  bool get isEmpty => id.isEmpty;

  @override
  String toString() => 'Issuer{id: $id, properties: $properties}';
}
