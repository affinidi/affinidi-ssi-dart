import 'dart:convert';

import 'package:http/http.dart' as http;

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import 'did_document/index.dart';
import 'did_key.dart';
import 'did_peer.dart';
import 'did_resolver.dart';
import 'did_web.dart';

/// A class for resolving multiple DID methods.
class UniversalDIDResolver implements DidResolver {
  /// The resolver address for external DID methods (optional).
  final String? resolverAddress;

  /// Creates a UniversalDIDResolver instance.
  ///
  /// [resolverAddress] is used for DID methods that require external resolution.
  UniversalDIDResolver({this.resolverAddress});

  /// Default DidResolver instance that implements the interface.
  static final DidResolver defaultResolver = UniversalDIDResolver();

  /// Resolves a DID Document for the given [did].
  ///
  /// For `did:key` resolution is performed internally.
  /// For other DID methods, a URL [resolverAddress] or an instance of a universal resolver is needed.
  ///
  /// [did] must be a valid DID string.
  /// [resolverAddress] is the URL of a universal resolver service.
  ///
  /// Returns a [DidDocument] containing the resolved DID document.
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  /// FIXME(FTL-20741) should use an URI as input or dedicated Did model
  @Deprecated(
      'Use UniversalDIDResolver instance with resolveDid() method or defaultResolver instead')
  static Future<DidDocument> resolve(
    /// The DID to resolve.
    String did, {
    /// The URL of a universal resolver service.
    String? resolverAddress,
  }) async {
    final resolver = UniversalDIDResolver(resolverAddress: resolverAddress);
    return resolver.resolveDid(did);
  }

  /// Resolves a DID Document for the given [did] using the DidResolver interface.
  ///
  /// For `did:key`, `did:peer`, and `did:web` resolution is performed internally.
  /// For other DID methods, this instance must be created with a [resolverAddress]
  /// pointing to a universal resolver service.
  ///
  /// [did] must be a valid DID string.
  ///
  /// Returns a [DidDocument] containing the resolved DID document.
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  /// - External resolution is required but no resolverAddress was provided
  @override
  Future<DidDocument> resolveDid(String did) async {
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
