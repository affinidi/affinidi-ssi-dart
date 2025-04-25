import '../../../../ssi.dart';
import '../../../util/json_util.dart';

class MutableIssuer {
  Uri? id;

  MutableIssuer({this.id});
  Map<String, dynamic> toJson() => cleanEmpty({
        'id': id?.toString(),
      });
}

class Issuer extends MutableIssuer {
  final Uri _id;

  @override
  Uri get id => _id;

  Issuer({required Uri id}) : _id = id;

  factory Issuer.fromJson(dynamic json) {
    Uri id;

    if (json is String) {
      id = Uri.parse(json);
    } else if (json is Uri) {
      id = json;
    } else if (json is Map<String, dynamic>) {
      id = getMandatoryUri(json, 'id');
    } else {
      throw SsiException(
        message: 'id should be a String or a Uri',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    return Issuer(id: id);
  }

  factory Issuer.uri(dynamic json) => Issuer.fromJson(json);
}
