import 'dart:convert';
import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:pointycastle/api.dart';
import 'package:ssi/src/credentials/issuance/embedded_proof.dart';
import 'package:ssi/src/credentials/issuance/embedded_proof_suite.dart';
import 'package:ssi/src/credentials/issuance/proof_purpose.dart';
import 'package:ssi/src/did/did_signer.dart';

import '../../util/base64_util.dart';

final _sha256 = Digest('SHA-256');

// FIXME what other naming convention could we use
class EcdsaSecp256k1Signature2019Options {
  final DidSigner signer;
  final ProofPurpose proofPurpose;

  EcdsaSecp256k1Signature2019Options({
    required this.signer,
    this.proofPurpose = ProofPurpose.assertionMethod,
  });
}

class EcdsaSecp256k1Signature2019
    implements EmbeddedProofSuite<EcdsaSecp256k1Signature2019Options> {
  static const _signatureType = "EcdsaSecp256k1Signature2019";
  static const _securityContext = "https://w3id.org/security/v2";

  @override
  Future<EmbeddedProof> createProof(
    Map<String, dynamic> document,
    EcdsaSecp256k1Signature2019Options options,
  ) async {
    final created = DateTime.now();
    final proof = {
      "@context": _securityContext,
      "type": _signatureType,
      "created": created.toIso8601String(),
      "verificationMethod": options.signer.keyId,
      "proofPurpose": options.proofPurpose.value,
    };

    document.remove('proof');

    final jws = await _computeVcHash(proof, document)
        .then((hash) => _computeAffinidJws(hash, options.signer));

    proof.remove('@context');
    proof['jws'] = jws;

    return EcdsaSecp256k1Signature2019Proof(
      type: 'EcdsaSecp256k1Signature2019',
      created: created,
      verificationMethod: options.signer.keyId,
      proofPurpose: options.proofPurpose.value,
      jws: jws,
    );
  }

  @override
  Future<VerificationResult> verifyProof(
    Map<String, dynamic> document,
    EcdsaSecp256k1Signature2019Options options,
  ) async {
    final copy = Map.of(document);
    final proof = copy.remove('proof');

    if (proof == null || proof is! Map<String, dynamic>) {
      return VerificationResult(
        isValid: false,
        issues: ['invalid or missing proof'],
      );
    }

    final originalJws = proof.remove('jws');
    proof["@context"] = _securityContext;

    final actualJws = await _computeVcHash(proof, copy)
        .then((hash) => _computeAffinidJws(hash, options.signer));

    return VerificationResult(
      isValid: originalJws == actualJws,
    );
  }

  static Future<Uint8List> _computeVcHash(
    Map<String, dynamic> proof,
    Map<String, dynamic> unsignedCredential,
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
      unsignedCredential,
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

class EcdsaSecp256k1Signature2019Proof extends EmbeddedProof {
  final String jws;

  EcdsaSecp256k1Signature2019Proof({
    required super.type,
    required super.created,
    required super.verificationMethod,
    required super.proofPurpose,
    required this.jws,
  });

  @override
  Map<String, dynamic> toJson() {
    final json = super.toJson();
    json['jws'] = jws;
    return json;
  }
}
