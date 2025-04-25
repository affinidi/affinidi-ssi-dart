import '../../../../ssi.dart';
import '../../../util/json_util.dart';

abstract interface class Issuer {
  Uri? get id;

  Map<String, dynamic> toJson() => {
        'id': id?.toString(),
      };
}

class MutableIssuer extends Issuer {
  @override
  Uri id;

  MutableIssuer(this.id);
}

class ParsedIssuer extends Issuer {
  Uri _id;

  @override
  Uri get id => _id;

  ParsedIssuer._(this._id);

  factory ParsedIssuer.fromJson(dynamic json) {
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

    return ParsedIssuer._(id);
  }
}
