import 'package:http/http.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
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

final RegExp didWebPattern =
    RegExp(r'^did:web:[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$');

bool isDidWeb(String didWeb) {
  return didWebPattern.hasMatch(didWeb);
}

class DidWeb {
  static Future<DidDocument> resolve(
    String didToResolve,
  ) async {
    if (!isDidWeb(didToResolve)) {
      throw SsiException(
        message: '`$didToResolve` does not match did:web regex',
        code: SsiExceptionType.invalidDidWeb.code,
      );
    }

    var res = await get(didWebToUri(didToResolve),
            headers: {'Accept': 'application/json'})
        .timeout(Duration(seconds: 30), onTimeout: () {
      return Response('Timeout', 408);
    });

    if (res.statusCode == 200) {
      return DidDocument.fromJson(res.body);
    } else {
      throw SsiException(
        message: 'Cant\'t fetch did-document for $didToResolve',
        code: SsiExceptionType.invalidDidWeb.code,
      );
    }
  }
}
