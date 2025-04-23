class Holder {
  final Uri id;

  Holder({
    required this.id,
  });

  factory Holder.fromJson(dynamic json) {
    if (json is String) {
      return Holder(id: Uri.parse(json));
    } else if (json is Map<String, dynamic>) {
      return Holder(id: Uri.parse(json['id'] as String));
    } else {
      throw ArgumentError('Holder must be a String or a Map');
    }
  }

  dynamic toJson() => id.toString();

  factory Holder.fromUri(String uri) => Holder(id: Uri.parse(uri));

  @override
  String toString() => 'Holder{id: ${id.toString()}}';
}
