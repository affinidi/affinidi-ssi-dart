import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_signer.dart';
import '../../did/did_verifier.dart';
import '../../did/universal_did_resolver.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../util/base64_util.dart';
import 'base_data_integrity_verifier.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';

const _dataIntegrityType = 'DataIntegrityProof';
const _ecdsaCryptosuite = 'ecdsa-rdfc-2019';
const _ecdsaJcsCryptosuite = 'ecdsa-jcs-2019';
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
  }) {
    final expectedScheme = cryptosuiteToScheme[_ecdsaCryptosuite];
    if (signer.signatureScheme != expectedScheme) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_ecdsaCryptosuite. Expected $expectedScheme.',
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
class DataIntegrityEcdsaVerifier extends BaseDataIntegrityVerifier {
  /// Constructs a new [DataIntegrityEcdsaVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  DataIntegrityEcdsaVerifier({
    required super.issuerDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
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
class DataIntegrityEcdsaJcsGenerator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  /// The DID signer used to produce the proof signature.
  final DidSigner signer;

  /// Constructs a new [DataIntegrityEcdsaJcsGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], and [domain] configure the proof metadata.
  DataIntegrityEcdsaJcsGenerator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
  }) {
    if (signer.signatureScheme != SignatureScheme.ecdsa_p256_sha256 &&
        signer.signatureScheme != SignatureScheme.ecdsa_p384_sha384) {
      throw SsiException(
        message:
            'Signer algorithm ${signer.signatureScheme} is not compatible with $_ecdsaJcsCryptosuite. Expected P-256 (SHA-256) or P-384 (SHA-384).',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
  }

  /// Generates an [EmbeddedProof] for the given [document].
  @override
  Future<EmbeddedProof> generate(Map<String, dynamic> document) async {
    final created = DateTime.now();
    final proof = {
      'type': _dataIntegrityType,
      'cryptosuite': _ecdsaJcsCryptosuite,
      'created': created.toIso8601String(),
      'verificationMethod': signer.keyId,
      'proofPurpose': proofPurpose?.value,
      'expires': expires?.toIso8601String(),
      'challenge': challenge,
      'domain': domain,
    };

    // Step 2: If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context
    final documentContext = document['@context'];
    if (documentContext != null) {
      proof['@context'] = documentContext;
    }

    // Proof Configuration validation per spec section 3.3.5
    _validateProofConfiguration(proof);

    document.remove('proof');

    final hash = await computeDataIntegrityJcsEcdsaHash(
      proof,
      document,
      signer.signatureScheme,
    );

    final signature = await _computeSignature(hash, signer);

    proof.remove('@context');
    proof['proofValue'] = signature;

    return EmbeddedProof(
      type: _dataIntegrityType,
      cryptosuite: _ecdsaJcsCryptosuite,
      created: created,
      verificationMethod: signer.keyId,
      proofPurpose: proofPurpose?.value,
      proofValue: signature,
      expires: expires,
      challenge: challenge,
      domain: domain,
    );
  }

  /// Validates proof configuration according to spec section 3.3.5.
  static void _validateProofConfiguration(Map<String, dynamic> proofConfig) {
    // Validate type and cryptosuite
    if (proofConfig['type'] != _dataIntegrityType ||
        proofConfig['cryptosuite'] != _ecdsaJcsCryptosuite) {
      throw SsiException(
        message:
            'Invalid proof configuration: type must be "$_dataIntegrityType" and cryptosuite must be "$_ecdsaJcsCryptosuite"',
        code: SsiExceptionType.unableToParseVerifiableCredential.code,
      );
    }

    // Validate created datetime if present
    final created = proofConfig['created'];
    if (created != null && created is String) {
      try {
        DateTime.parse(created);
      } catch (e) {
        throw SsiException(
          message:
              'Invalid created datetime: must be a valid XMLSCHEMA11-2 datetime',
          code: SsiExceptionType.unableToParseVerifiableCredential.code,
        );
      }
    }

    // Validate expires datetime if present
    final expires = proofConfig['expires'];
    if (expires != null && expires is String) {
      try {
        DateTime.parse(expires);
      } catch (e) {
        throw SsiException(
          message:
              'Invalid expires datetime: must be a valid XMLSCHEMA11-2 datetime',
          code: SsiExceptionType.unableToParseVerifiableCredential.code,
        );
      }
    }
  }

  static Future<String> _computeSignature(
    Uint8List hash,
    DidSigner signer,
  ) async {
    final signature = await signer.sign(hash);
    return 'z${base58BitcoinEncode(signature)}';
  }
}

/// Verifies Data Integrity Proofs signed with the ecdsa-jcs-2019 cryptosuite.
///
/// Canonicalizes using JCS and hashes the credential and proof separately, then verifies
/// the combined hash against the provided proof signature using the issuer's DID key.
class DataIntegrityEcdsaJcsVerifier extends BaseDataIntegrityVerifier {
  /// Constructs a new [DataIntegrityEcdsaJcsVerifier].
  ///
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  DataIntegrityEcdsaJcsVerifier({
    required super.issuerDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
  });

  @override
  Future<VerificationResult> verify(Map<String, dynamic> document,
      {DateTime Function() getNow = DateTime.now}) async {
    final copy = Map.of(document);
    final documentContext = document['@context'];

    // Call the parent verify method but intercept the hash computation
    return await _verifyWithCorrectContext(copy, documentContext, getNow);
  }

  /// Custom verification that ensures JCS uses document @context during hash computation
  Future<VerificationResult> _verifyWithCorrectContext(
    Map<String, dynamic> document,
    dynamic documentContext,
    DateTime Function() getNow,
  ) async {
    final copy = Map.of(document);
    final proof = copy.remove('proof');

    // Basic validation (duplicated from base class as these are private)
    if (proof == null || proof is! Map<String, dynamic>) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof'],
      );
    }

    if (proof['type'] != expectedProofType) {
      return VerificationResult.invalid(
        errors: ['invalid proof type, expected $expectedProofType'],
      );
    }

    // Expiry validation
    final expires = proof['expires'];
    if (expires != null) {
      DateTime expiryDate;
      if (expires is String) {
        try {
          expiryDate = DateTime.parse(expires);
        } catch (e) {
          return VerificationResult.invalid(
            errors: ['invalid expires format'],
          );
        }
      } else {
        return VerificationResult.invalid(
          errors: ['expires must be a string'],
        );
      }

      if (getNow().isAfter(expiryDate)) {
        return VerificationResult.invalid(
          errors: ['proof has expired'],
        );
      }
    }

    final Uri verificationMethod;
    try {
      verificationMethod = Uri.parse(proof['verificationMethod'] as String);
    } catch (e) {
      return VerificationResult.invalid(
        errors: ['invalid or missing proof.verificationMethod'],
      );
    }

    final originalProofValue = proof.remove(proofValueField);
    if (originalProofValue == null) {
      return VerificationResult.invalid(
        errors: ['missing $proofValueField'],
      );
    }

    // For JCS, set proof @context to document @context (not standard DI context)
    proof['@context'] = documentContext;

    // Ensure proof structure matches what was used during signing
    // The generator includes these fields even if null, so we need them for consistent hashing
    if (!proof.containsKey('expires')) {
      proof['expires'] = null;
    }
    if (!proof.containsKey('challenge')) {
      proof['challenge'] = null;
    }
    if (!proof.containsKey('domain')) {
      proof['domain'] = null;
    }

    // For ecdsa-jcs-2019, we need to dynamically determine the signature scheme
    // by examining the verification method since it supports both P-256 and P-384
    final verificationMethodUri = proof['verificationMethod'] as String?;
    if (verificationMethodUri == null) {
      throw SsiException(
        message: 'Missing verificationMethod in proof',
        code: SsiExceptionType.unableToParseVerifiableCredential.code,
      );
    }

    // Resolve the DID to get the verification method
    final didDocument = await UniversalDIDResolver.resolve(issuerDid);

    // Find the verification method in the DID document
    final vm = didDocument.verificationMethod
        .where((vm) =>
            vm.id == verificationMethodUri ||
            vm.id.endsWith('#${verificationMethodUri.split('#').last}'))
        .firstOrNull;

    if (vm == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodUri not found in DID document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Get the JWK and determine the signature scheme
    final jwk = vm.asJwk();
    final jwkMap = jwk.toJson();
    final signatureScheme = getEcdsaJcsSignatureScheme(jwkMap);

    final hash =
        await computeDataIntegrityJcsEcdsaHash(proof, copy, signatureScheme);

    final isValid = await verifySignature(
        originalProofValue as String, issuerDid, verificationMethod, hash);

    if (!isValid) {
      return VerificationResult.invalid(
        errors: ['signature invalid'],
      );
    }

    return VerificationResult.ok();
  }

  @override
  String get expectedProofType => _dataIntegrityType;

  @override
  String get expectedCryptosuite => _ecdsaJcsCryptosuite;

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
    // For ecdsa-jcs-2019, we need to dynamically determine the signature scheme
    // by examining the verification method since it supports both P-256 and P-384
    final verificationMethodUri = proof['verificationMethod'] as String?;
    if (verificationMethodUri == null) {
      throw SsiException(
        message: 'Missing verificationMethod in proof',
        code: SsiExceptionType.unableToParseVerifiableCredential.code,
      );
    }

    // Resolve the DID to get the verification method
    final didDocument = await UniversalDIDResolver.resolve(issuerDid);

    // Find the verification method in the DID document
    final verificationMethod = didDocument.verificationMethod
        .where((vm) =>
            vm.id == verificationMethodUri ||
            vm.id.endsWith('#${verificationMethodUri.split('#').last}'))
        .firstOrNull;

    if (verificationMethod == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodUri not found in DID document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Get the JWK and determine the signature scheme
    final jwk = verificationMethod.asJwk();
    final jwkMap = jwk.toJson();
    final signatureScheme = getEcdsaJcsSignatureScheme(jwkMap);

    return computeDataIntegrityJcsEcdsaHash(
        proof, unsignedCredential, signatureScheme);
  }

  @override
  Future<bool> verifySignature(
    String proofValue,
    String issuerDid,
    Uri verificationMethod,
    Uint8List hash,
  ) async {
    // For ecdsa-jcs-2019, we need custom verification since the signature scheme
    // is determined dynamically from the verification method

    final Uint8List signature;
    if (!proofValue.startsWith('z')) {
      throw SsiException(
        message:
            'JCS cryptosuite $_ecdsaJcsCryptosuite requires base58-btc multibase encoding (z prefix)',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }
    signature = base58BitcoinDecode(proofValue.substring(1));

    // Resolve the DID to get the verification method
    final didDocument = await UniversalDIDResolver.resolve(issuerDid);

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
    final signatureScheme = getEcdsaJcsSignatureScheme(jwkMap);

    final verifier = await DidVerifier.create(
      algorithm: signatureScheme,
      kid: verificationMethod.toString(),
      issuerDid: issuerDid,
    );
    return verifier.verify(hash, signature);
  }
}
