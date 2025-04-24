import 'dart:convert';

import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/types.dart';

class SignatureObject implements JsonObject {
  Map<String, dynamic>? protected;
  Map<String, dynamic>? header;
  late String signature;

  SignatureObject({this.protected, this.header, required this.signature});

  SignatureObject.fromJson(dynamic jsonObject) {
    var sig = credentialToMap(jsonObject);
    if (sig.containsKey('protected')) {
      protected = jsonDecode(
          utf8.decode(base64Decode(addPaddingToBase64(sig['protected']!))));
    }
    header = sig['header'];
    if (sig.containsKey('signature')) {
      signature = sig['signature'];
    } else {
      throw Exception('signature value is needed in SignatureObject');
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    if (protected != null) {
      jsonObject['protected'] = removePaddingFromBase64(
          base64UrlEncode(utf8.encode(jsonEncode(protected!))));
    }
    if (header != null) jsonObject['header'] = header;
    jsonObject['signature'] = signature;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
