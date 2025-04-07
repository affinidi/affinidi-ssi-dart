import 'dart:convert';
import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:pointycastle/api.dart';

import '../../did/did_signer.dart';
import '../../util/base64_util.dart';
import '../models/v1/vc_data_model_v1.dart';

final _sha256 = Digest('SHA-256');

class LdVcDm1 {
  /// Prepare a signed VC using embedded proof
  Future<VcDataModelV1> issueEmbeddedProof({
    required VcDataModelV1 unsignedCredential,
    required DidSigner signer,
  }) async {
    unsignedCredential.issuer = signer.did;

    final proof = {
      "@context": "https://w3id.org/security/v2",
      "type": "EcdsaSecp256k1Signature2019",
      "created": DateTime.now().toIso8601String(),
      "verificationMethod": signer.keyId,
      "proofPurpose": "assertionMethod"
    };

    final jws = await _computeVcHash(proof, unsignedCredential)
        .then((hash) => _computeAffinidJws(hash, signer));

    proof.remove('@context');
    proof['jws'] = jws;

    final copy = unsignedCredential.toJson();
    copy['proof'] = proof;

    return VcDataModelV1.fromJson(copy);
  }

  static Future<Uint8List> _computeVcHash(
    Map<String, dynamic> proof,
    VcDataModelV1 unsignedCredential,
  ) async {
    final normalizedProof = await JsonLdProcessor.normalize(
      proof,
      options: JsonLdOptions(
        safeMode: true,
        documentLoader: loadDocument,
      ),
    );
    final proofDigest = _sha256.process(
      utf8.encode(normalizedProof),
    );

    final normalizedContent = await JsonLdProcessor.normalize(
      unsignedCredential.toJson(),
      options: JsonLdOptions(
        safeMode: true,
        documentLoader: loadDocument,
      ),
    );

    final contentDigest = Digest('SHA-256').process(
      utf8.encode(normalizedContent),
    );

    final payloadToSign = Uint8List.fromList(proofDigest + contentDigest);
    return payloadToSign;
  }

  /// Compute a JWS that is compatible with what our [BE outputs](https://gitlab.com/affinidi/foundational/genesis/libs/core/tiny-lds-ecdsa-secp256k1-2019/-/blob/main/src/secp256k1key.ts?ref_type=heads#L49)
  static Future<String> _computeAffinidJws(
    Uint8List payloadToSign,
    DidSigner signer,
  ) async {
    final encodedHeader = base64UrlNoPadEncode(
      utf8.encode(
        jsonEncode(
          {
            'alg': 'ES256K',
            'b64': false,
            'crit': ['b64'],
          },
        ),
      ),
    );

    final jwsToSign = Uint8List.fromList(
      utf8.encode(encodedHeader) + utf8.encode('.') + payloadToSign,
    );

    final jws = base64UrlNoPadEncode(await signer.sign(jwsToSign));

    return '$encodedHeader..$jws';
  }
}
