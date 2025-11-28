import 'package:http/http.dart';

import '../credentials/models/field_types/context.dart';
import '../did/public_key_utils.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/public_key.dart';
import 'did_document/index.dart';
import 'did_manager/verification_relationship.dart';

/// Converts a `did:web` identifier into a [Uri] pointing to its DID document.
Uri didWebToUri(String didWeb) {
  var did = didWeb.replaceFirst('did:web:', '');
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

/// A utility class for working with the "did:web" method.
class DidWeb {
  /// Generates a [DidDocument] for a did:web method.

  static DidDocument generateDocument({
    required String did,
    required List<String> verificationMethodIds,
    required List<PublicKey> publicKeys,
    required Map<VerificationRelationship, List<String>> relationships,
    required List<ServiceEndpoint> serviceEndpoints,
  }) {
    final context = [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1'
    ];

    final vms = <EmbeddedVerificationMethod>[];
    for (var i = 0; i < verificationMethodIds.length; i++) {
      final vmId = verificationMethodIds[i];
      final pubKey = publicKeys[i];
      vms.add(VerificationMethodMultibase(
        id: vmId,
        controller: did,
        type: 'Multikey',
        publicKeyMultibase: toMultiBase(toMultikey(pubKey.bytes, pubKey.type)),
      ));
    }

    return DidDocument.create(
      context: JsonLdContext.fromJson(context),
      id: did,
      verificationMethod: vms,
      authentication:
          relationships[VerificationRelationship.authentication] ?? [],
      keyAgreement: relationships[VerificationRelationship.keyAgreement] ?? [],
      assertionMethod:
          relationships[VerificationRelationship.assertionMethod] ?? [],
      capabilityInvocation:
          relationships[VerificationRelationship.capabilityInvocation] ?? [],
      capabilityDelegation:
          relationships[VerificationRelationship.capabilityDelegation] ?? [],
      service: serviceEndpoints,
    );
  }

  /// Returns a did:web identifier for the given domain.
  ///
  /// Example: getDid('example.com') => 'did:web:example.com'
  static String getDid(Uri domain) {
    return 'did:web:${_parseDomain(domain)}';
  }

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

    try {
      var res = await get(didWebToUri(didToResolve),
              headers: {'Accept': 'application/json'})
          .timeout(const Duration(seconds: 30), onTimeout: () {
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
    } catch (e) {
      // Re-throw if already an SsiException
      if (e is SsiException) rethrow;

      // Handle any HTTP errors (connection refused, timeouts, etc.)
      throw SsiException(
        message: 'Failed to fetch DID Web document for $didToResolve: $e',
        code: SsiExceptionType.invalidDidWeb.code,
      );
    }
  }

  /// Parses and normalizes the domain according to did:web specification.
  ///
  /// The did:web spec encodes:
  /// - Ports using %3A (e.g., example.com:3000 → example.com%3A3000)
  /// - Paths using : as separator (e.g., /user/alice → :user:alice)
  ///
  /// Accepts domains in various formats:
  /// - Uri.parse('example.com') → 'example.com'
  /// - Uri.parse('https://example.com') → 'example.com'
  /// - Uri.parse('https://example.com:3000') → 'example.com%3A3000'
  /// - Uri.parse('https://example.com:3000/user/alice') → 'example.com%3A3000:user:alice'
  /// - Uri.parse('example.com/user/alice') → 'example.com:user:alice'
  static String _parseDomain(Uri uri) {
    // Build the did:web domain format
    var result = uri.host;

    // Encode port with %3A if present
    if (uri.hasPort && uri.port != 443 && uri.port != 80) {
      result = '$result%3A${uri.port}';
    }

    // Encode path with : separators (remove leading slash)
    if (uri.path.isNotEmpty && uri.path != '/') {
      var path = uri.path;
      if (path.startsWith('/')) {
        path = path.substring(1);
      }
      if (path.endsWith('/')) {
        path = path.substring(0, path.length - 1);
      }
      // Replace / with :
      path = path.replaceAll('/', ':');
      result = '$result:$path';
    }

    return result;
  }
}
