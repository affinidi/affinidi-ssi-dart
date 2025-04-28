import '../../../util/json_util.dart';

abstract interface class _HolderInterface {
  Uri? get id;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({'id': id?.toString()});
}

class MutableHolder extends _HolderInterface {
  Uri? id;

  MutableHolder({this.id});

  factory MutableHolder.fromJson(dynamic json) {
    final id = getUri(json, 'id');
    return MutableHolder(id: id);
  }

  factory MutableHolder.uri(dynamic json) => MutableHolder.fromJson(json);
}

class Holder extends _HolderInterface {
  final Uri _id;

  @override
  Uri get id => _id;

  Holder({required Uri id}) : _id = id;

  factory Holder.fromJson(dynamic json) {
    final id = getMandatoryUri(json, 'id');
    return Holder(id: id);
  }

  factory Holder.uri(dynamic json) => Holder.fromJson(json);
}
