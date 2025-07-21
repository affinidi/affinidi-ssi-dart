// lib/src/did/did_resolver.dart

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
class UniversalDIDResolver {
  /// Default instance for backward compatibility.
  static final UniversalDIDResolver defaultInstance = UniversalDIDResolver();

  /// Default DidResolver instance that wraps the UniversalDIDResolver.
  static final DidResolver defaultResolver =
      _UniversalDidResolverAdapter(defaultInstance);

  /// Static method for resolving DIDs using the default instance.
  /// Maintains backward compatibility with existing code.
  ///
  /// [did] must be a valid DID string.
  /// [resolverAddress] is the URL of a universal resolver service (optional).
  ///
  /// Returns a [DidDocument] containing the resolved DID document.
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  static Future<DidDocument> resolve(
    String did, {
    String? resolverAddress,
  }) async {
    return defaultInstance.resolveInternal(did,
        resolverAddress: resolverAddress);
  }

  /// Internal resolve method used by both static and instance calls.
  Future<DidDocument> resolveInternal(
    String did, {
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

/// Adapter class that wraps UniversalDIDResolver to implement the DidResolver interface.
class _UniversalDidResolverAdapter implements DidResolver {
  final UniversalDIDResolver _resolver;

  _UniversalDidResolverAdapter(this._resolver);

  @override
  Future<DidDocument> resolve(
    String did, {
    String? resolverAddress,
  }) {
    return _resolver.resolveInternal(did, resolverAddress: resolverAddress);
  }
}
