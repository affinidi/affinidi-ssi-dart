import 'dart:convert';

import 'package:http/http.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import 'did_document/index.dart';

/// The URL for the Cheqd DID resolver service.
String cheqdResolverUrl = 'https://resolver.cheqd.net/1.0/identifiers/';

/// A utility class for working with the "did:cheqd" method.
class DidCheqd {
  /// Resolves a [DidDocument] for a given DID.
  ///
  /// [didToResolve] - The DID to resolve.
  ///
  /// Returns a [DidDocument] object.
  static Future<DidDocument> resolve(
    String didToResolve,
  ) async {
    if (!didToResolve.startsWith('did:cheqd')) {
      throw SsiException(
        message: '`$didToResolve` is not did:cheqd DID',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }

    var res = await get(Uri.parse('$cheqdResolverUrl$didToResolve'),
            headers: {'Accept': 'application/json'})
        .timeout(const Duration(seconds: 30), onTimeout: () {
      return Response('Timeout', 408);
    });

    if (res.statusCode == 200) {
      final responseJson = jsonDecode(res.body);
      return DidDocument.fromJson(responseJson['didDocument']);
    } else {
      throw SsiException(
        message: 'Failed to fetch DID Cheqd document for $didToResolve',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }
  }
}
