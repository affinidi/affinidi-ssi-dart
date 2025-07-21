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

  /// Default instance for backward compatibility.
  static final UniversalDIDResolver defaultInstance = UniversalDIDResolver();

  /// Default DidResolver instance that implements the interface.
  static final DidResolver defaultResolver = UniversalDIDResolver();

  @override
  Future<DidDocument> resolve(
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
      return resolveWithAddress(did, resolverAddress: resolverAddress);
    }
  }

  /// Resolves a DID Document for DIDs that require external resolution.
  ///
  /// [did] must be a valid DID string.
  /// [resolverAddress] overrides the instance's resolver address if provided.
  ///
  /// Returns a [DidDocument] containing the resolved DID document.
  ///
  /// Throws [SsiException] if:
  /// - The DID is invalid
  /// - The resolution fails
  /// - No resolver address is available for external DIDs
  Future<DidDocument> resolveWithAddress(
    String did, {
    String? resolverAddress,
  }) async {
    final address = resolverAddress ?? this.resolverAddress;
    if (address == null) {
      throw SsiException(
        message:
            'This DID can only be resolved using a universal resolver. Please provide a resolver address.',
        code: SsiExceptionType.unableToResolveDid.code,
      );
    }

    final res = await http
        .get(Uri.parse('$address/1.0/identifiers/$did'))
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
