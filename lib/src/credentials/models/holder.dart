class Holder {
  final String id;

  Holder({
    required this.id,
  });

  factory Holder.fromJson(dynamic json) {
    if (json is String) {
      return Holder(id: json);
    } else if (json is Map<String, dynamic>) {
      final id = json['id'] as String;
      final propertiesMap = Map<String, dynamic>.from(json);
      propertiesMap.remove('id');
      return Holder(id: id);
    } else {
      throw ArgumentError('Holder must be a String or a Map');
    }
  }

  dynamic toJson() => id;

  factory Holder.fromUri(String uri) => Holder(id: uri);

  @override
  String toString() => 'Holder{id: $id}';
}
