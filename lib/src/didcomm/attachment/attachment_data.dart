import 'dart:convert';

import 'package:ssi/src/didcomm/utils.dart';
import 'package:ssi/src/types.dart';

class AttachmentData implements JsonObject {
  dynamic jws;
  String? hash;
  List<String>? links;
  String? base64;
  dynamic json;

  AttachmentData({this.jws, this.hash, this.links, this.base64, this.json});

  AttachmentData.fromJson(dynamic jsonData) {
    Map<String, dynamic> decoded = credentialToMap(jsonData);
    jws = decoded['jws'];
    hash = decoded['hash'];
    if (decoded.containsKey('links')) links = decoded['links']?.cast<String>();
    base64 = decoded['base64'];
    json = decoded['json'];
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonData = {};
    if (jws != null) jsonData['jws'] = jws;
    if (hash != null) jsonData['hash'] = hash;
    if (links != null) jsonData['links'] = links;
    if (base64 != null) jsonData['base64'] = base64;
    if (json != null) jsonData['json'] = json;
    return jsonData;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
