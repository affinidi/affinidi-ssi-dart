import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_signer.dart';
import '../../did/public_key_utils.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import 'base_data_integrity_verifier.dart';
import 'base_jcs_generator.dart';
import 'base_jcs_verifier.dart';
import 'data_integrity_context_util.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';

const _dataIntegrityType = 'DataIntegrityProof';
const _eddsaCryptosuite = 'eddsa-rdfc-2022';
const _eddsaJcsCryptosuite = 'eddsa-jcs-2022';
const _dataIntegrityContext = 'https://w3id.org/security/data-integrity/v2';

/// Generates Data Integrity Proofs using the eddsa-rdfc-2022 cryptosuite.
///
/// Signs Verifiable Credentials by normalizing the credential and the proof separately,
/// hashing them, and then signing the combined hash using a [DidSigner].
class DataIntegrityEddsaRdfcGenerator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  /// The DID signer used to produce the proof signature.
  final DidSigner signer;

  /// Constructs a new [DataIntegrityEddsaRdfcGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], and [domain] configure the proof metadata.
  DataIntegrityEddsaRdfcGenerator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
    super.nonce,
    super.proofValueMultiBase,
  }) {
    final expectedSchemes = cryptosuiteToScheme[_eddsaCryptosuite];
    if (expectedSchemes == null ||
        !expectedSchemes.contains(signer.signatureScheme)) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_eddsaCryptosuite. Expected $expectedSchemes.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
  }

  /// Generates an [EmbeddedProof] for the given [document].
  @override
  Future<EmbeddedProof> generate(Map<String, dynamic> document) async {
    final created = DateTime.now();
    // Validate credential @context contains Data Integrity or VC v2 context
    DataIntegrityContextUtil.validate(document);
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
      'nonce': nonce,
    };

    document.remove('proof');

    final cacheLoadDocument = createCacheDocumentLoader(customDocumentLoader);
    final hash =
        await computeDataIntegrityHash(proof, document, cacheLoadDocument);
    final proofValue = await _computeProofValue(hash, signer);

    proof.remove('@context');
    proof['proofValue'] = proofValue;

    return EmbeddedProof(
      type: _dataIntegrityType,
      cryptosuite: _eddsaCryptosuite,
      created: created,
      verificationMethod: signer.keyId,
      proofPurpose: proofPurpose?.value,
      proofValue: proofValue,
      expires: expires,
      challenge: challenge,
      domain: domain,
      nonce: nonce,
    );
  }

  Future<String> _computeProofValue(
    Uint8List hash,
    DidSigner signer,
  ) async {
    final signature = await signer.sign(hash);
    return toMultiBase(
      signature,
      base: proofValueMultiBase,
    );
  }
}

/// Generates Data Integrity Proofs using the eddsa-rdfc-2022 cryptosuite.
///
/// Signs Verifiable Credentials by normalizing the credential and the proof separately,
/// hashing them, and then signing the combined hash using a [DidSigner].
///
/// @deprecated Use [DataIntegrityEddsaRdfcGenerator] instead for consistent naming.
@Deprecated(
    'Use DataIntegrityEddsaRdfcGenerator instead for consistent naming.')
typedef DataIntegrityEddsaGenerator = DataIntegrityEddsaRdfcGenerator;

/// Verifies Data Integrity Proofs signed with the eddsa-rdfc-2022 cryptosuite.
///
/// Normalizes and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
@Deprecated(
    'Use DataIntegrityEddsaRdfcVerifier for eddsa-rdfc-2022 cryptosuite instead')
class DataIntegrityRdfcEddsaVerifier extends BaseDataIntegrityVerifier {
  /// Constructs a new [DataIntegrityRdfcEddsaVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  /// [didResolver]: Optional custom DID resolver for offline/test verification.
  DataIntegrityRdfcEddsaVerifier({
    required super.issuerDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
    super.didResolver,
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
      didResolver: didResolver,
    );
  }
}

/// Verifies Data Integrity Proofs signed with the eddsa-rdfc-2022 cryptosuite.
///
/// Normalizes and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
class DataIntegrityEddsaRdfcVerifier extends BaseDataIntegrityVerifier {
  /// Constructs a new [DataIntegrityEddsaRdfcVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  /// [didResolver]: Optional custom DID resolver for offline/test verification.
  DataIntegrityEddsaRdfcVerifier({
    required super.issuerDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
    super.didResolver,
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
      didResolver: didResolver,
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
  /// [challenge], [domain], and [proofValueMultiBase] configure the proof metadata.
  DataIntegrityEddsaJcsGenerator({
    required super.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
    super.nonce,
    super.proofValueMultiBase,
  });

  @override
  String get cryptosuite => _eddsaJcsCryptosuite;

  @override
  HashingAlgorithm get hashingAlgorithm => HashingAlgorithm.sha256;

  @override
  void validateSignerCompatibility(DidSigner signer) {
    final expectedSchemes = cryptosuiteToScheme[_eddsaJcsCryptosuite];
    if (expectedSchemes == null ||
        !expectedSchemes.contains(signer.signatureScheme)) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_eddsaJcsCryptosuite. Expected $expectedSchemes.',
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
  /// [verifierDid]: The DID of the issuer whose credential this verifier will validate.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  /// [didResolver]: Optional custom DID resolver for offline/test verification.
  DataIntegrityEddsaJcsVerifier({
    required super.verifierDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
    super.didResolver,
  });

  @override
  String get expectedJcsCryptosuite => _eddsaJcsCryptosuite;

  @override
  HashingAlgorithm get hashingAlgorithm => HashingAlgorithm.sha256;
}
