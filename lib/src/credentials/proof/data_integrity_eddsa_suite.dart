import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_signer.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../util/base64_util.dart';
import 'base_data_integrity_verifier.dart';
import 'base_jcs_generator.dart';
import 'base_jcs_verifier.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';

const _dataIntegrityType = 'DataIntegrityProof';
const _eddsaCryptosuite = 'eddsa-rdfc-2022';
const _eddsaJcsCryptosuite = 'eddsa-jcs-2022';
const _dataIntegrityContext = 'https://w3id.org/security/data-integrity/v1';

/// Generates Data Integrity Proofs using the eddsa-rdfc-2022 cryptosuite.
///
/// Signs Verifiable Credentials by normalizing the credential and the proof separately,
/// hashing them, and then signing the combined hash using a [DidSigner].
class DataIntegrityEddsaGenerator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  /// The DID signer used to produce the proof signature.
  final DidSigner signer;

  /// Constructs a new [DataIntegrityEddsaGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], and [domain] configure the proof metadata.
  DataIntegrityEddsaGenerator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
  }) {
    final expectedScheme = cryptosuiteToScheme[_eddsaCryptosuite];
    if (signer.signatureScheme != expectedScheme) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_eddsaCryptosuite. Expected $expectedScheme.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
  }

  /// Generates an [EmbeddedProof] for the given [document].
  @override
  Future<EmbeddedProof> generate(Map<String, dynamic> document) async {
    final created = DateTime.now();
    final proof = {
      '@context': _dataIntegrityContext,
      'type': _dataIntegrityType,
      'cryptosuite': _eddsaCryptosuite,
      'created': created.toIso8601String(),
      'verificationMethod': signer.keyId,
      'proofPurpose': proofPurpose?.value,
      'expires': expires?.toIso8601String(),
      'challenge': challenge,
      'domain': domain,
    };

    document.remove('proof');

    final cacheLoadDocument = createCacheDocumentLoader(customDocumentLoader);
    final hash =
        await computeDataIntegrityHash(proof, document, cacheLoadDocument);
    final signature = await _computeSignature(hash, signer);

    proof.remove('@context');
    proof['proofValue'] = signature;

    return EmbeddedProof(
      type: _dataIntegrityType,
      cryptosuite: _eddsaCryptosuite,
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

/// Verifies Data Integrity Proofs signed with the eddsa-rdfc-2022 cryptosuite.
///
/// Normalizes and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
class DataIntegrityEddsaVerifier extends BaseDataIntegrityVerifier {
  /// Constructs a new [DataIntegrityEddsaVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  DataIntegrityEddsaVerifier({
    required super.issuerDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
  });

  @override
  String get expectedProofType => _dataIntegrityType;

  @override
  String get expectedCryptosuite => _eddsaCryptosuite;

  @override
  String get contextUrl => _dataIntegrityContext;

  @override
  String get proofValueField => 'proofValue';

  @override
  Future<Uint8List> computeSignatureHash(
    Map<String, dynamic> proof,
    Map<String, dynamic> unsignedCredential,
    Future<RemoteDocument?> Function(Uri url, LoadDocumentOptions? options)
        documentLoader,
  ) async {
    return computeDataIntegrityHash(proof, unsignedCredential, documentLoader);
  }

  @override
  Future<bool> verifySignature(
    String proofValue,
    String issuerDid,
    Uri verificationMethod,
    Uint8List hash,
  ) async {
    return verifyDataIntegritySignature(
      proofValue,
      issuerDid,
      verificationMethod,
      hash,
      _eddsaCryptosuite,
    );
  }
}

/// Generates Data Integrity Proofs using the eddsa-jcs-2022 cryptosuite.
///
/// Signs Verifiable Credentials by canonicalizing the credential and the proof using JCS,
/// hashing them, and then signing the combined hash using a [DidSigner].
class DataIntegrityEddsaJcsGenerator extends BaseJcsGenerator {
  /// Constructs a new [DataIntegrityEddsaJcsGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], and [domain] configure the proof metadata.
  DataIntegrityEddsaJcsGenerator({
    required super.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
  });

  @override
  String get cryptosuite => _eddsaJcsCryptosuite;

  @override
  HashingAlgorithm get hashingAlgorithm => HashingAlgorithm.sha256;

  @override
  void validateSignerCompatibility(DidSigner signer) {
    final expectedScheme = cryptosuiteToScheme[_eddsaJcsCryptosuite];
    if (signer.signatureScheme != expectedScheme) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_eddsaJcsCryptosuite. Expected $expectedScheme.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
  }
}

/// Verifies Data Integrity Proofs signed with the eddsa-jcs-2022 cryptosuite.
///
/// Canonicalizes using JCS and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
class DataIntegrityEddsaJcsVerifier extends BaseJcsVerifier {
  /// Constructs a new [DataIntegrityEddsaJcsVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  DataIntegrityEddsaJcsVerifier({
    required super.issuerDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
  });

  @override
  String get expectedJcsCryptosuite => _eddsaJcsCryptosuite;

  @override
  HashingAlgorithm get hashingAlgorithm => HashingAlgorithm.sha256;
}
