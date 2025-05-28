import 'dart:convert';
import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:pointycastle/api.dart';

import '../../did/did_signer.dart';
import '../../did/did_verifier.dart';
import '../../types.dart';
import '../../util/base64_util.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';

const _dataIntegrityType = 'DataIntegrityProof';
const _ecdsaCryptosuite = 'ecdsa-rdfc-2019';
const _dataIntegrityContext = 'https://w3id.org/security/data-integrity/v1';

/// Generates Data Integrity Proofs using the ecdsa-rdfc-2019 cryptosuite.
///
/// Signs Verifiable Credentials by normalizing the credential and the proof separately,
/// hashing them, and then signing the combined hash using a [DidSigner].
class DataIntegrityEcdsaGenerator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  /// The DID signer used to produce the proof signature.
  final DidSigner signer;

  /// Constructs a new [DataIntegrityEcdsaGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], and [domain] configure the proof metadata.
  DataIntegrityEcdsaGenerator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
  });

  /// Generates an [EmbeddedProof] for the given [document].
  @override
  Future<EmbeddedProof> generate(Map<String, dynamic> document) async {
    final created = DateTime.now();
    final proof = {
      '@context': _dataIntegrityContext,
      'type': _dataIntegrityType,
      'cryptosuite': _ecdsaCryptosuite,
      'created': created.toIso8601String(),
      'verificationMethod': signer.keyId,
      'proofPurpose': proofPurpose?.value,
      'expires': expires?.toIso8601String(),
      'challenge': challenge,
      'domain': domain,
    };

    document.remove('proof');

    final cacheLoadDocument = _cacheLoadDocument(customDocumentLoader);
    final hash =
        await _computeDataIntegrityHash(proof, document, cacheLoadDocument);
    final signature = await _computeSignature(hash, signer);

    proof.remove('@context');
    proof['proofValue'] = signature;

    return EmbeddedProof(
      type: _dataIntegrityType,
      cryptosuite: _ecdsaCryptosuite,
      created: created,
      verificationMethod: signer.keyId,
      proofPurpose: proofPurpose?.value,
      proofValue: signature,
      expires: expires,
      challenge: challenge,
      domain: domain,
    );
  }

  static Future<String> _computeSignature(
    Uint8List hash,
    DidSigner signer,
  ) async {
    final signature = await signer.sign(hash);
    return base64UrlNoPadEncode(signature);
  }
}

/// Verifies Data Integrity Proofs signed with the ecdsa-rdfc-2019 cryptosuite.
///
/// Normalizes and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
class DataIntegrityEcdsaVerifier extends EmbeddedProofSuiteVerifyOptions
    implements EmbeddedProofVerifier {
  /// The DID of the issuer expected to have signed the credential.
  final String issuerDid;

  /// Function to supply the current timestamp for proof expiry validation.
  final DateTime Function() getNow;

  /// Optional domain to validate within the proof.
  final List<String>? domain;

  /// Optional challenge string to validate within the proof.
  final String? challenge;

  /// Constructs a new [DataIntegrityEcdsaVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  DataIntegrityEcdsaVerifier({
    required this.issuerDid,
    this.getNow = DateTime.now,
    this.domain,
    this.challenge,
    super.customDocumentLoader,
  });

  /// Verifies the proof embedded in the provided [document].
  ///
  /// Returns a [VerificationResult] indicating success or listing errors.
  @override
  Future<VerificationResult> verify(Map<String, dynamic> document,
      {DateTime Function() getNow = DateTime.now}) async {
    final copy = Map.of(document);
    final proof = copy.remove('proof');

    if (proof == null || proof is! Map<String, dynamic>) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof'],
      );
    }

    if (proof['type'] != _dataIntegrityType) {
      return VerificationResult.invalid(
        errors: ['invalid proof type, expected $_dataIntegrityType'],
      );
    }

    if (proof['cryptosuite'] != _ecdsaCryptosuite) {
      return VerificationResult.invalid(
        errors: ['invalid cryptosuite, expected $_ecdsaCryptosuite'],
      );
    }

    var now = getNow();

    final expires = proof['expires'];
    if (expires != null && now.isAfter(DateTime.parse(expires as String))) {
      return VerificationResult.invalid(errors: ['proof has expired']);
    }

    Uri verificationMethod;
    try {
      verificationMethod = Uri.parse(proof['verificationMethod'] as String);
    } catch (e) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof.verificationMethod'],
      );
    }

    final originalProofValue = proof.remove('proofValue');
    if (originalProofValue == null) {
      return VerificationResult.invalid(
        errors: ['missing proofValue'],
      );
    }

    proof['@context'] = _dataIntegrityContext;

    final cacheLoadDocument = _cacheLoadDocument(customDocumentLoader);
    final hash =
        await _computeDataIntegrityHash(proof, copy, cacheLoadDocument);
    final isValid = await _verifySignature(
        originalProofValue as String, issuerDid, verificationMethod, hash);

    if (!isValid) {
      return VerificationResult.invalid(
        errors: ['signature invalid'],
      );
    }

    return VerificationResult.ok();
  }
}

Future<Uint8List> _computeDataIntegrityHash(
  Map<String, dynamic> proof,
  Map<String, dynamic> unsignedCredential,
  Future<RemoteDocument?> Function(Uri url, LoadDocumentOptions? options)
      documentLoader,
) async {
  final normalizedProof = await JsonLdProcessor.normalize(
    proof,
    options: JsonLdOptions(
      safeMode: true,
      documentLoader: documentLoader,
    ),
  );
  final proofConfigHash = Digest('SHA-256').process(
    utf8.encode(normalizedProof),
  );

  final normalizedContent = await JsonLdProcessor.normalize(
    unsignedCredential,
    options: JsonLdOptions(
      safeMode: true,
      documentLoader: documentLoader,
    ),
  );
  final transformedDocumentHash = Digest('SHA-256').process(
    utf8.encode(normalizedContent),
  );

  return Uint8List.fromList(proofConfigHash + transformedDocumentHash);
}

Future<bool> _verifySignature(
  String proofValue,
  String issuerDid,
  Uri verificationMethod,
  Uint8List hash,
) async {
  final signature = base64UrlNoPadDecode(proofValue);

  final verifier = await DidVerifier.create(
    algorithm: SignatureScheme.ecdsa_p256_sha256,
    kid: verificationMethod.toString(),
    issuerDid: issuerDid,
  );
  return verifier.verify(hash, signature);
}

typedef _LibDocumentLoader = Future<RemoteDocument> Function(
  Uri url,
  LoadDocumentOptions? options,
);

_LibDocumentLoader _cacheLoadDocument(
  DocumentLoader customLoader,
) =>
    (Uri url, LoadDocumentOptions? options) async {
      final fromCache = _documentCache[url];
      if (fromCache != null) {
        return Future.value(fromCache);
      }

      final custom = await customLoader(url);
      if (custom != null) {
        return Future.value(RemoteDocument(document: custom));
      }

      return loadDocument(url, options);
    };

final _documentCache = <Uri, RemoteDocument>{
  Uri.parse('https://w3id.org/security/data-integrity/v1'): RemoteDocument(
    document: jsonDecode(r'''
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    },
    "cryptosuite": "https://w3id.org/security#cryptosuite"
  }
}
'''),
  ),
};
