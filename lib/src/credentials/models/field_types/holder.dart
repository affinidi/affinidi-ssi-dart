import '../../../../ssi.dart';
import '../../../util/json_util.dart';

class MutableHolder {
  Uri? id;

  MutableHolder({this.id});

  Map<String, dynamic> toJson() => {
        'id': id?.toString(),
      };
}

class Holder extends MutableHolder {
  final Uri _id;

  @override
  Uri get id => _id;

  Holder._(this._id);

  factory Holder.fromJson(dynamic json) {
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

    return Holder._(id);
  }
}
