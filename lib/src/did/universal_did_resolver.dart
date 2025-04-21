// lib/src/did/did_resolver.dart

import 'dart:convert';
import 'package:http/http.dart' as http;

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import 'did_document.dart';
import 'did_key.dart';
import 'did_peer.dart';
import 'did_web.dart';

/// A class for resolving multiple DID methods.
class UniversalDIDResolver {
  /// Resolves a DID Document for the given [did].
  ///
  /// For `did:key` resolution is performed internally.
  /// For other DID methods, ab URL [resolverAddress] o an instance of a universal resolver is needed.
  ///
  /// [did] must be a valid DID string.
  /// [resolverAddress] is the URL of a universal resolver service
  ///
  /// Returns a [DidDocument] containing the resolved DID document.
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  /// FIXME(FTL-20741) should use an URI as input or dedicated Did model
  static Future<DidDocument> resolve(
    /// The DID to resolve.
    String did, {
    /// The URL of a universal resolver service.
    String? resolverAddress,
  }) async {
    if (did.startsWith('did:key')) {
      return DidKey.resolve(did);
    } else if (did.startsWith('did:peer')) {
      return DidPeer.resolve(did);
    } else if (did.startsWith('did:web')) {
      return DidWeb.resolve(did);
    } else {
      if (resolverAddress == null) {
        throw SsiException(
          message:
              'This DID can only be resolved using a universal resolver. Please provide a resolver address.',
          code: SsiExceptionType.unableToResolveDid.code,
        );
      }

      final res = await http
          .get(Uri.parse('$resolverAddress/1.0/identifiers/$did'))
          .timeout(const Duration(seconds: 30));

      if (res.statusCode == 200) {
        final didResolution = jsonDecode(res.body);
        return DidDocument.fromJson(didResolution['didDocument']);
      } else {
        throw SsiException(
          message: 'Bad status code ${res.statusCode}',
          code: SsiExceptionType.unableToResolveDid.code,
        );
      }
    }
  }
}
