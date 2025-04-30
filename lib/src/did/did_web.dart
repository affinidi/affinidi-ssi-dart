import 'package:http/http.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import 'did_document/index.dart';

/// Converts a `did:web` identifier into a [Uri] pointing to its DID document.
Uri didWebToUri(String didWeb) {
  String did = didWeb.replaceFirst('did:web:', '');
  did = did.replaceAll(':', '/');
  did = did.replaceAll('%3A', ':');
  did = did.replaceAll('%2B', '/');
  did = 'https://$did';
  final asUri = Uri.parse(did);
  if (asUri.hasEmptyPath) {
    did = '$did/.well-known';
  }
  did = '$did/did.json';

  return Uri.parse(did);
}

/// A utility class for working with the "did:peer" method.
class DidWeb {
  /// Resolves a [DidDocument] for a given DID.
  ///
  /// [didToResolve] - The DID to resolve.
  ///
  /// Returns a [DidDocument] object.
  static Future<DidDocument> resolve(
    String didToResolve,
  ) async {
    if (!didToResolve.startsWith('did:web')) {
      throw SsiException(
        message: '`$didToResolve` is not did:web DID',
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
        message: 'Failed to fetch DID Web document for $didToResolve',
        code: SsiExceptionType.invalidDidWeb.code,
      );
    }
  }
}
