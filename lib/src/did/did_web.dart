import 'package:http/http.dart';

import '../key_pair/key_pair.dart';
import 'did_document.dart';

Uri didWebToUri(String didWeb) {
  var did = didWeb.replaceFirst('did:web:', '');
  did = did.replaceAll(':', '/');
  did = did.replaceAll('%3A', ':');
  did = did.replaceAll('%2B', '/');
  did = 'https://$did';
  var asUri = Uri.parse(did);
  if (asUri.hasEmptyPath) {
    did = '$did/.well-known';
  }
  did = '$did/did.json';

  return Uri.parse(did);
}

class DidWeb {
  // FIXME build proper DID document
  static Future<DidDocument> create(
    List<KeyPair> keyPairs,
    String did,
  ) async {
    return DidDocument(
      id: did,
    );
  }

  static Future<DidDocument> resolve(
    String didToResolve,
  ) async {
    var res = await get(didWebToUri(didToResolve),
            headers: {'Accept': 'application/json'})
        .timeout(Duration(seconds: 30), onTimeout: () {
      return Response('Timeout', 408);
    });
    if (res.statusCode == 200) {
      return DidDocument.fromJson(res.body);
    } else {
      throw Exception('Cant\'t fetch did-document for $didToResolve');
    }
  }
}
