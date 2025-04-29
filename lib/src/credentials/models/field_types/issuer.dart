import '../../../util/json_util.dart';

abstract interface class _IssuerInterface {
  Uri? get id;

  /// Converts this status to a JSON-serializable map.
  ///
  /// Returns a map containing the 'type' field and 'id' field if present.
  Map<String, dynamic> toJson() => cleanEmpty({'id': id?.toString()});
}

class MutableIssuer extends _IssuerInterface {
  Uri? id;

  MutableIssuer({this.id});

  factory MutableIssuer.fromJson(dynamic json) {
    final id = getUri(json, 'id');
    return MutableIssuer(id: id);
  }

  factory MutableIssuer.uri(dynamic json) => MutableIssuer.fromJson(json);
}

class Issuer extends MutableIssuer {
  final Uri _id;

  @override
  Uri get id => _id;

  Issuer({required Uri id}) : _id = id;

  factory Issuer.fromJson(dynamic json) {
    final id = getMandatoryUri(json, 'id');
    return Issuer(id: id);
  }

  factory Issuer.uri(dynamic json) => Issuer.fromJson(json);
}
