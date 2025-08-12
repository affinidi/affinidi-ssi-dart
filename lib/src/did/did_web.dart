import 'package:http/http.dart';

import '../../ssi.dart';
import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../json_ld/context.dart';
import '../key_pair/public_key.dart';
import 'did_document/index.dart';
import 'public_key_utils.dart';

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

/// A utility class for working with the "did:peer" method.
class DidWeb {
  static const _context = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/jws-2020/v1',
  ];

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
  }

  /// This method takes a public key and creates a DID document
  ///
  /// [publicKey] The public key used to create the DID
  ///
  /// Returns a [DidDocument].
  ///
  /// Throws [SsiException] if the public key is invalid
  static DidDocument generateDocument({
    required String did,
    required List<String> verificationMethodIds,
    required List<PublicKey> publicKeys,
    required Map<VerificationRelationship, List<String>> relationships,
    required List<ServiceEndpoint> serviceEndpoints,
  }) {
    final vms = <VerificationMethodJwk>[];
    for (var i = 0; i < verificationMethodIds.length; i++) {
      final vmId = verificationMethodIds[i];
      vms.add(VerificationMethodJwk(
        id: vmId,
        controller: did,
        type: 'JsonWebKey2020',
        publicKeyJwk: Jwk.fromJson(keyToJwk(publicKeys[i])),
      ));
    }

    return DidDocument.create(
      context: Context.fromJson(_context),
      id: publicKeys[0].id.split('#')[0],
      verificationMethod: vms,
      authentication:
          relationships[VerificationRelationship.authentication] ?? [],
      keyAgreement: relationships[VerificationRelationship.keyAgreement] ?? [],
      assertionMethod:
          relationships[VerificationRelationship.assertionMethod] ?? [],
      service: serviceEndpoints,
    );
  }
}
