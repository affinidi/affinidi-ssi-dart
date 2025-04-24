import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart';
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

  Future<void> resolveData() async {
    if (json != null) {
      return;
    } else if (base64 != null) {
      json = jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(base64!))));
    } else if (links != null && links!.isNotEmpty) {
      if (hash == null) throw Exception('If links are used hash must be given');

      for (var link in links!) {
        try {
          var res = await get(Uri.parse(link),
              headers: {'Accept': 'application/json'});

          if (res.statusCode == 200) {
            String body = res.body;
            // body should be a json object
            try {
              var baseDecoded = base64Decode(addPaddingToBase64(hash!));
              var data = Uint8List.fromList(utf8.encode(body));

              var correctHash = checkMultiHash(baseDecoded, data);

              if (correctHash) {
                json = jsonDecode(body);
              } else {
                // now check if answer is json-Object with attachment property
                var decoded = jsonDecode(body);
                if (decoded is Map<String, dynamic>) {
                  String attachmentJson = decoded['attachment'];

                  var attData = Uint8List.fromList(utf8.encode(attachmentJson));
                  if (!checkMultiHash(baseDecoded, attData)) {
                    throw Exception(
                        'Hash does not match data (Code: 23482304928)');
                  }
                  json = jsonDecode(attachmentJson);
                } else if (decoded is List) {
                  var attach = decoded.first as Map;
                  var attData =
                      Uint8List.fromList(utf8.encode(jsonEncode(attach)));
                  if (!checkMultiHash(baseDecoded, attData)) {
                    throw Exception(
                        'Hash does not match data (Code: 23482304928)');
                  }
                  json = attach;
                }
              }
            } catch (e) {
              throw Exception('Hash is not a valid base64 '
                  'encoded multihash ($e) (Code: 34982093)');
            }

            break;
          }
        } catch (e) {
          throw Exception('Cant load link data for $link due to `$e` '
              '(Code: 49382903)');
        }
      }
      if (json == null) throw Exception('No data found');
    } else {
      throw Exception('No data');
    }
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

  //TODO: for now sign and verify only support json encodeable content
  // Future<void> sign(WalletStore wallet, didToSignWith) async {
  //   Map<String, dynamic> payload;
  //   if (json != null) {
  //     payload = json!;
  //   } else if (base64 != null) {
  //     payload =
  //         jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(base64!))));
  //   } else {
  //     throw Exception('nothing to sign');
  //   }
  //   jws = await signStringOrJson(
  //       wallet: wallet,
  //       didToSignWith: didToSignWith,
  //       toSign: payload,
  //       detached: true);
  // }

  // Future<bool> verifyJws(String expectedDid) async {
  //   if (jws == null) throw Exception('no signature found');
  //   Map<String, dynamic> payload;
  //   if (json != null) {
  //     payload = json!;
  //   } else if (base64 != null) {
  //     payload =
  //         jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(base64!))));
  //   } else {
  //     throw Exception('nothing to sign');
  //   }
  //   return verifyStringSignature(jws,
  //       expectedDid: expectedDid, toSign: payload);
  // }
}
