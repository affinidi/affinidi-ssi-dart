import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_signer.dart';
import '../../did/public_key_utils.dart';
import '../../did/universal_did_resolver.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import 'base_data_integrity_verifier.dart';
import 'base_jcs_generator.dart';
import 'base_jcs_verifier.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';
import 'jcs_utils.dart';

const _dataIntegrityType = 'DataIntegrityProof';
const _ecdsaCryptosuite = 'ecdsa-rdfc-2019';
const _ecdsaJcsCryptosuite = 'ecdsa-jcs-2019';
const _dataIntegrityContext = 'https://w3id.org/security/data-integrity/v2';

/// Generates Data Integrity Proofs using the ecdsa-rdfc-2019 cryptosuite.
///
/// Signs Verifiable Credentials by normalizing the credential and the proof separately,
/// hashing them, and then signing the combined hash using a [DidSigner].
class DataIntegrityEcdsaRdfcGenerator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  /// The DID signer used to produce the proof signature.
  final DidSigner signer;

  /// Constructs a new [DataIntegrityEcdsaRdfcGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], and [domain] configure the proof metadata.
  DataIntegrityEcdsaRdfcGenerator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
    super.proofValueMultiBase,
  }) {
    final expectedSchemes = cryptosuiteToScheme[_ecdsaCryptosuite];
    if (expectedSchemes == null ||
        !expectedSchemes.contains(signer.signatureScheme)) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_ecdsaCryptosuite. Expected $expectedSchemes.',
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
      'cryptosuite': _ecdsaCryptosuite,
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
    final proofValue = await _computeProofValue(hash, signer);

    proof.remove('@context');
    proof['proofValue'] = proofValue;

    return EmbeddedProof(
      type: _dataIntegrityType,
      cryptosuite: _ecdsaCryptosuite,
      created: created,
      verificationMethod: signer.keyId,
      proofPurpose: proofPurpose?.value,
      proofValue: proofValue,
      expires: expires,
      challenge: challenge,
      domain: domain,
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

/// Generates Data Integrity Proofs using the ecdsa-rdfc-2019 cryptosuite.
///
/// Signs Verifiable Credentials by normalizing the credential and the proof separately,
/// hashing them, and then signing the combined hash using a [DidSigner].
///
/// @deprecated Use [DataIntegrityEcdsaRdfcGenerator] instead for consistent naming.
@Deprecated(
    'Use DataIntegrityEcdsaRdfcGenerator instead for consistent naming.')
typedef DataIntegrityEcdsaGenerator = DataIntegrityEcdsaRdfcGenerator;

/// Verifies Data Integrity Proofs signed with the ecdsa-rdfc-2019 cryptosuite.
///
/// Normalizes and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
@Deprecated(
    'Use DataIntegrityEcdsaRdfcVerifier for ecdsa-rdfc-2019 cryptosuite instead')
class DataIntegrityEcdsaVerifier extends BaseDataIntegrityVerifier {
  /// Constructs a new [DataIntegrityEcdsaVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  /// [didResolver]: Optional custom DID resolver for offline/test verification.
  DataIntegrityEcdsaVerifier({
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
  String get expectedCryptosuite => _ecdsaCryptosuite;

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
      _ecdsaCryptosuite,
    );
  }
}

/// Verifies Data Integrity Proofs signed with the ecdsa-rdfc-2019 cryptosuite.
///
/// Normalizes and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
class DataIntegrityEcdsaRdfcVerifier extends BaseDataIntegrityVerifier {
  /// Constructs a new [DataIntegrityEcdsaRdfcVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  /// [didResolver]: Optional custom DID resolver for offline/test verification.
  DataIntegrityEcdsaRdfcVerifier({
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
  String get expectedCryptosuite => _ecdsaCryptosuite;

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
      _ecdsaCryptosuite,
    );
  }
}

/// Generates Data Integrity Proofs using the ecdsa-jcs-2019 cryptosuite.
///
/// Signs Verifiable Credentials by canonicalizing the credential and the proof using JCS,
/// hashing them, and then signing the combined hash using a [DidSigner].
class DataIntegrityEcdsaJcsGenerator extends BaseJcsGenerator {
  /// Constructs a new [DataIntegrityEcdsaJcsGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], [domain], and [proofValueMultiBase] configure the proof metadata.
  DataIntegrityEcdsaJcsGenerator({
    required super.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
    super.proofValueMultiBase,
  });

  @override
  String get cryptosuite => _ecdsaJcsCryptosuite;

  @override
  HashingAlgorithm get hashingAlgorithm =>
      signer.signatureScheme.hashingAlgorithm;

  @override
  void validateSignerCompatibility(DidSigner signer) {
    if (signer.signatureScheme != SignatureScheme.ecdsa_p256_sha256 &&
        signer.signatureScheme != SignatureScheme.ecdsa_p384_sha384) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_ecdsaJcsCryptosuite. Expected P-256 (SHA-256) or P-384 (SHA-384).',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
  }
}

/// Verifies Data Integrity Proofs signed with the ecdsa-jcs-2019 cryptosuite.
///
/// Canonicalizes using JCS and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
class DataIntegrityEcdsaJcsVerifier extends BaseJcsVerifier {
  /// Constructs a new [DataIntegrityEcdsaJcsVerifier].
  ///
  /// [verifierDid]: The DID of the issuer whose credential this verifier will validate.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  /// [didResolver]: Optional custom DID resolver for offline/test verification.
  DataIntegrityEcdsaJcsVerifier({
    required super.verifierDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
    super.didResolver,
  });

  @override
  String get expectedJcsCryptosuite => _ecdsaJcsCryptosuite;

  @override
  HashingAlgorithm get hashingAlgorithm {
    // For ECDSA JCS, we can't determine the hash algorithm statically
    // since it supports both P-256 (SHA-256) and P-384 (SHA-384).
    // The actual algorithm is determined dynamically in computeSignatureHash.
    throw UnsupportedError(
        'ECDSA JCS requires dynamic hash algorithm determination');
  }

  @override
  Future<Uint8List> computeSignatureHash(
    Map<String, dynamic> proof,
    Map<String, dynamic> unsignedCredential,
    Future<RemoteDocument?> Function(Uri url, LoadDocumentOptions? options)
        documentLoader,
  ) async {
    // For ecdsa-jcs-2019, we need to dynamically determine the signature scheme
    // by examining the verification method since it supports both P-256 and P-384
    final signatureScheme =
        await _getSignatureSchemeFromVerificationMethod(proof);
    return JcsUtils.computeDataIntegrityJcsHash(
        proof, unsignedCredential, signatureScheme.hashingAlgorithm);
  }

  @override
  Future<SignatureScheme> getSignatureScheme(Uri verificationMethod) async {
    return _getSignatureSchemeFromDid(verificationMethod);
  }

  /// Determines the signature scheme from the verification method.
  Future<SignatureScheme> _getSignatureSchemeFromVerificationMethod(
      Map<String, dynamic> proof) async {
    final verificationMethodUri = proof['verificationMethod'] as String?;
    if (verificationMethodUri == null) {
      throw SsiException(
        message: 'Missing verificationMethod in proof',
        code: SsiExceptionType.unableToParseVerifiableCredential.code,
      );
    }

    return _getSignatureSchemeFromDid(Uri.parse(verificationMethodUri));
  }

  /// Determines the signature scheme from the verification method.
  Future<SignatureScheme> _getSignatureSchemeFromDid(
      Uri verificationMethod) async {
    // Resolve the DID to get the verification method
    final resolver = didResolver ?? UniversalDIDResolver.defaultResolver;
    final didDocument = await resolver.resolveDid(issuerDid);

    // Find the verification method in the DID document
    final vm = didDocument.verificationMethod
        .where((vm) =>
            vm.id == verificationMethod.toString() ||
            vm.id.endsWith('#${verificationMethod.toString().split('#').last}'))
        .firstOrNull;

    if (vm == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethod not found in DID document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Get the JWK and determine the signature scheme
    final jwk = vm.asJwk();
    final jwkMap = jwk.toJson();
    return getEcdsaSignatureScheme(jwkMap);
  }
}
