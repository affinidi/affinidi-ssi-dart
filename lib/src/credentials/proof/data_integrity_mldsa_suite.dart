import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';
import 'package:pqcrypto/pqcrypto.dart';

import '../../did/did_resolver.dart';
import '../../did/did_signer.dart';
import '../../did/public_key_utils.dart';
import '../../did/universal_did_resolver.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../utility.dart';
import 'base_data_integrity_verifier.dart';
import 'base_jcs_generator.dart';
import 'base_jcs_verifier.dart';
import 'data_integrity_context_util.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';

const _dataIntegrityType = 'DataIntegrityProof';
const _mldsaRdfcCryptosuite = 'mldsa44-rdfc-2024';
const _mldsaJcsCryptosuite = 'mldsa44-jcs-2024';
const _dataIntegrityContext = 'https://w3id.org/security/data-integrity/v2';

/// Expected sizes for ML-DSA-44 (FIPS 204 Table 2).
const int _mlDsa44SignatureBytes = 2420;
const int _mlDsa44PublicKeyBytes = 1312;

/// Multikey prefix bytes for ML-DSA-44 public keys.
const List<int> _mlDsa44MultikeyPrefix = [0x90, 0x24];

/// Verifies an ML-DSA-44 Data Integrity signature.
///
/// This is the dedicated ML-DSA-44 verification path. It does not use
/// [DidVerifier] (which relies on JWK/JWA and cannot handle post-quantum
/// algorithms).
///
/// Steps:
/// 1. Decode the multibase [proofValue] (expected 2420 bytes).
/// 2. Resolve the DID document for [issuerDid].
/// 3. Find the verification method matching [verificationMethod].
/// 4. Extract the raw public key bytes (1312 bytes) from the multikey.
/// 5. Verify [hashData] against the signature using ML-DSA-44.
///
/// Returns `false` (never throws) for any malformed or invalid input.
Future<bool> verifyMldsa44DataIntegritySignature(
  String proofValue,
  String issuerDid,
  Uri verificationMethod, {
  required Uint8List hashData,
  DidResolver? didResolver,
}) async {
  try {
    // Step 1: decode signature.
    final signature = multiBaseToUint8List(proofValue);
    if (signature.length != _mlDsa44SignatureBytes) {
      return false;
    }

    // Step 2: resolve DID document.
    final resolver = didResolver ?? UniversalDIDResolver.defaultResolver;
    final didDocument = await resolver.resolveDid(issuerDid);

    // Step 3: find the matching verification method.
    final vmId = verificationMethod.toString();
    final fragment = vmId.contains('#') ? vmId.split('#').last : vmId;
    final vm = didDocument.verificationMethod.firstWhere(
      (m) => m.id == vmId || m.id.endsWith('#$fragment'),
      orElse: () => throw SsiException(
        message: 'Verification method $vmId not found in DID document',
        code: SsiExceptionType.invalidDidDocument.code,
      ),
    );

    // Step 4: extract public key from multikey bytes.
    final multikeyBytes = vm.asMultiKey();
    if (multikeyBytes.length < 2 + _mlDsa44PublicKeyBytes) {
      return false;
    }
    if (multikeyBytes[0] != _mlDsa44MultikeyPrefix[0] ||
        multikeyBytes[1] != _mlDsa44MultikeyPrefix[1]) {
      // Not an ML-DSA-44 key.
      return false;
    }
    final pk = multikeyBytes.sublist(2);
    if (pk.length != _mlDsa44PublicKeyBytes) {
      return false;
    }

    // Step 5: verify signature.
    return MlDsa.verify(pk, hashData, signature, DilithiumParams.mlDsa44);
  } catch (_) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// RDFC generator
// ---------------------------------------------------------------------------

/// Generates Data Integrity Proofs using the mldsa44-rdfc-2024 cryptosuite.
///
/// Signs Verifiable Credentials by normalizing the credential and proof via
/// RDFC (RDF Dataset Canonicalization), hashing them with SHA-256, and signing
/// the combined hash using ML-DSA-44.
///
/// This is an **experimental** post-quantum cryptosuite.
class DataIntegrityMldsaRdfcGenerator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  /// The DID signer used to produce the proof signature.
  final DidSigner signer;

  /// Constructs a new [DataIntegrityMldsaRdfcGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters configure the proof metadata.
  DataIntegrityMldsaRdfcGenerator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
    // Default to base64url-no-pad per W3C vc-di-quantum-resistant draft.
    MultiBase proofValueMultiBase = MultiBase.base64UrlNoPad,
  }) : super(proofValueMultiBase: proofValueMultiBase) {
    final expectedSchemes = cryptosuiteToScheme[_mldsaRdfcCryptosuite];
    if (expectedSchemes == null ||
        !expectedSchemes.contains(signer.signatureScheme)) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_mldsaRdfcCryptosuite. Expected $expectedSchemes.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
  }

  @override
  Future<EmbeddedProof> generate(Map<String, dynamic> document) async {
    final created = DateTime.now();
    final nonce = randomId();
    DataIntegrityContextUtil.validate(document);
    final proof = {
      '@context': _dataIntegrityContext,
      'type': _dataIntegrityType,
      'cryptosuite': _mldsaRdfcCryptosuite,
      'created': created.toIso8601String(),
      'verificationMethod': signer.didKeyId,
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
      cryptosuite: _mldsaRdfcCryptosuite,
      created: created,
      verificationMethod: signer.didKeyId,
      proofPurpose: proofPurpose?.value,
      proofValue: proofValue,
      expires: expires,
      challenge: challenge,
      domain: domain,
      nonce: nonce,
    );
  }

  Future<String> _computeProofValue(Uint8List hash, DidSigner signer) async {
    final signature = await signer.sign(hash);
    return toMultiBase(signature, base: proofValueMultiBase);
  }
}

// ---------------------------------------------------------------------------
// RDFC verifier
// ---------------------------------------------------------------------------

/// Verifies Data Integrity Proofs signed with the mldsa44-rdfc-2024 cryptosuite.
///
/// This is an **experimental** post-quantum cryptosuite verifier.
class DataIntegrityMldsaRdfcVerifier extends BaseDataIntegrityVerifier {
  /// Constructs a new [DataIntegrityMldsaRdfcVerifier].
  DataIntegrityMldsaRdfcVerifier({
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
  String get expectedCryptosuite => _mldsaRdfcCryptosuite;

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
    return verifyMldsa44DataIntegritySignature(
      proofValue,
      issuerDid,
      verificationMethod,
      hashData: hash,
      didResolver: didResolver,
    );
  }
}

// ---------------------------------------------------------------------------
// JCS generator
// ---------------------------------------------------------------------------

/// Generates Data Integrity Proofs using the mldsa44-jcs-2024 cryptosuite.
///
/// Signs Verifiable Credentials by canonicalizing the credential and proof via
/// JCS (RFC 8785), hashing them with SHA-256, and signing the combined hash
/// using ML-DSA-44.
///
/// This is an **experimental** post-quantum cryptosuite.
class DataIntegrityMldsaJcsGenerator extends BaseJcsGenerator {
  /// Constructs a new [DataIntegrityMldsaJcsGenerator].
  DataIntegrityMldsaJcsGenerator({
    required super.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
    // Default to base64url-no-pad per W3C vc-di-quantum-resistant draft.
    MultiBase proofValueMultiBase = MultiBase.base64UrlNoPad,
  }) : super(proofValueMultiBase: proofValueMultiBase);

  @override
  String get cryptosuite => _mldsaJcsCryptosuite;

  @override
  HashingAlgorithm get hashingAlgorithm => HashingAlgorithm.sha256;

  @override
  void validateSignerCompatibility(DidSigner signer) {
    final expectedSchemes = cryptosuiteToScheme[_mldsaJcsCryptosuite];
    if (expectedSchemes == null ||
        !expectedSchemes.contains(signer.signatureScheme)) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_mldsaJcsCryptosuite. Expected $expectedSchemes.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// JCS verifier
// ---------------------------------------------------------------------------

/// Verifies Data Integrity Proofs signed with the mldsa44-jcs-2024 cryptosuite.
///
/// This is an **experimental** post-quantum cryptosuite verifier.
class DataIntegrityMldsaJcsVerifier extends BaseJcsVerifier {
  /// Constructs a new [DataIntegrityMldsaJcsVerifier].
  DataIntegrityMldsaJcsVerifier({
    required super.verifierDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
    super.didResolver,
  });

  @override
  String get expectedJcsCryptosuite => _mldsaJcsCryptosuite;

  @override
  HashingAlgorithm get hashingAlgorithm => HashingAlgorithm.sha256;

  /// Overrides the base class implementation to use the ML-DSA-44 dedicated
  /// verification path instead of [DidVerifier], which cannot verify
  /// post-quantum signatures.
  @override
  Future<bool> verifySignature(
    String proofValue,
    String issuerDid,
    Uri verificationMethod,
    Uint8List hash,
  ) async {
    return verifyMldsa44DataIntegritySignature(
      proofValue,
      issuerDid,
      verificationMethod,
      hashData: hash,
      didResolver: didResolver,
    );
  }
}
