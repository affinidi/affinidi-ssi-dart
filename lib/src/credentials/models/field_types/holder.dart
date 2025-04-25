import '../../../../ssi.dart';
import '../../../util/json_util.dart';

abstract interface class Holder {
  Uri? get id;

  Map<String, dynamic> toJson() => {
        'id': id?.toString(),
      };
}

class MutableHolder extends Holder {
  @override
  Uri id;

  MutableHolder(this.id);
}

class ParsedHolder extends Holder {
  final Uri _id;

  @override
  Uri get id => _id;

  ParsedHolder._(this._id);

  factory ParsedHolder.fromJson(dynamic json) {
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

    return ParsedHolder._(id);
  }
}
