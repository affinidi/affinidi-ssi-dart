import 'dart:typed_data';

import '../../did/did_signer.dart';
import '../../types.dart';
import 'embedded_proof.dart';
import 'embedded_proof_suite.dart';
import 'jcs_utils.dart';

/// Base class for Data Integrity proof generators using JCS canonicalization.
///
/// Provides common functionality for JCS-based cryptosuites like ecdsa-jcs-2019
/// and eddsa-jcs-2022, eliminating code duplication and ensuring consistency.
abstract class BaseJcsGenerator extends EmbeddedProofSuiteCreateOptions
    implements EmbeddedProofGenerator {
  /// The DID signer used to produce the proof signature.
  final DidSigner signer;

  /// The cryptosuite identifier for this generator.
  String get cryptosuite;

  /// Constructs a new [BaseJcsGenerator].
  ///
  /// [signer]: The DID signer responsible for creating the proof signature.
  /// Optional parameters like [proofPurpose], [customDocumentLoader], [expires],
  /// [challenge], and [domain] configure the proof metadata.
  BaseJcsGenerator({
    required this.signer,
    super.proofPurpose,
    super.customDocumentLoader,
    super.expires,
    super.challenge,
    super.domain,
    super.proofValueMultiBase,
  }) {
    validateSignerCompatibility(signer);
  }

  /// Validates that the signer is compatible with this cryptosuite.
  ///
  /// Subclasses must implement this to check signature scheme compatibility.
  /// Should throw SsiException if the signer is incompatible.
  void validateSignerCompatibility(DidSigner signer);

  /// Gets the hashing algorithm for this cryptosuite.
  ///
  /// Subclasses must implement this to specify the appropriate hash algorithm.
  HashingAlgorithm get hashingAlgorithm;

  /// Generates an [EmbeddedProof] for the given [document].
  @override
  Future<EmbeddedProof> generate(Map<String, dynamic> document) async {
    final created = DateTime.now();
    final proof = JcsUtils.createBaseProofConfiguration(
      cryptosuite: cryptosuite,
      created: created,
      verificationMethod: signer.keyId,
      proofPurpose: proofPurpose?.value,
      expires: expires,
      challenge: challenge,
      domain: domain,
    );

    // Set proof context to document context if present
    final documentContext = document['@context'];
    if (documentContext != null) {
      proof['@context'] = documentContext;
    }

    // Validate proof configuration structure
    JcsUtils.validateProofConfiguration(proof, cryptosuite);

    // Remove proof from document for signing
    document.remove('proof');

    // Compute hash and signature
    final hash = await JcsUtils.computeDataIntegrityJcsHash(
      proof,
      document,
      hashingAlgorithm,
    );
    final signature = await computeSignature(hash, signer);

    // Remove context and add signature to proof
    proof.remove('@context');
    proof['proofValue'] = signature;

    return EmbeddedProof(
      type: JcsUtils.dataIntegrityType,
      cryptosuite: cryptosuite,
      created: created,
      verificationMethod: signer.keyId,
      proofPurpose: proofPurpose?.value,
      proofValue: signature,
      expires: expires,
      challenge: challenge,
      domain: domain,
    );
  }

  /// Computes the signature for the given hash.
  ///
  /// Signs the hash using the signer and encodes it with multibase for JCS.
  Future<String> computeSignature(Uint8List hash, DidSigner signer) async {
    final signature = await signer.sign(hash);
    return JcsUtils.encodeJcsSignature(signature, base: proofValueMultiBase);
  }
}
