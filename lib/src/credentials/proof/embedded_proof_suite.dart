import '../../types.dart';
import '../proof/proof_purpose.dart';
import 'embedded_proof.dart';

/// Function type for loading external documents referenced in proofs.
///
/// Takes a [url] and returns the document content as a JSON map, or null if not found.
typedef DocumentLoader = Future<Map<String, dynamic>?> Function(Uri url);

/// Options for creating cryptographic proofs.
///
/// Contains settings that control how a proof is created, such as
/// custom document loaders for resolving external references.
class EmbeddedProofSuiteCreateOptions {
  /// The document loader to use when creating proofs.
  final DocumentLoader customDocumentLoader;

  /// The date and time when this proof expires.
  final DateTime? expires;

  /// The domains this proof is bound to.
  /// Can be a single string or a list of strings.
  final List<String>? domain;

  /// A challenge to prevent replay attacks.
  final String? challenge;

  /// The purpose of embedded proof.
  final ProofPurpose? proofPurpose;

  /// Creates a new [EmbeddedProofSuiteCreateOptions] instance.
  ///
  /// Uses [_noOpLoader] as the default document loader if none is provided.
  /// [expires] - Specify expiry of proof.
  /// [domain] - Specify one or more security domains in which the proof is meant to be used.
  /// [challenge] - Specify challenge for domain in proof.
  EmbeddedProofSuiteCreateOptions({
    this.customDocumentLoader = _noOpLoader,
    this.proofPurpose = ProofPurpose.assertionMethod,
    this.expires,
    this.domain,
    this.challenge,
  });
}

/// Options for verifying cryptographic proofs.
///
/// Contains settings that control how a proof is verified, such as
/// custom document loaders for resolving external references.
class EmbeddedProofSuiteVerifyOptions {
  /// The document loader to use when verifying proofs.
  final DocumentLoader customDocumentLoader;

  /// Creates a new [EmbeddedProofSuiteVerifyOptions] instance.
  ///
  /// Uses [_noOpLoader] as the default document loader if none is provided.
  EmbeddedProofSuiteVerifyOptions({this.customDocumentLoader = _noOpLoader});
}

/// Base class for cryptographic proof suites that can create and verify embedded proofs.
///
/// Implementations provide specific algorithms for creating and verifying
/// cryptographic proofs within documents like verifiable credentials.
abstract class EmbeddedProofSuite<
    CreateOptions extends EmbeddedProofSuiteCreateOptions,
    VerifyOptions extends EmbeddedProofSuiteVerifyOptions> {
  /// Creates a proof for the specified [document] using the provided [options].
  ///
  /// Returns an [EmbeddedProof] that can be added to the document.
  Future<EmbeddedProof> createProof(
    Map<String, dynamic> document,
    CreateOptions options,
  );

  /// Verifies the proof in the specified [document] using the provided [options].
  ///
  /// Returns a [VerificationResult] indicating whether the proof is valid.
  Future<VerificationResult> verifyProof(
    Map<String, dynamic> document,
    VerifyOptions options,
  );
}

/// A no-operation document loader that always returns null.
Future<Map<String, dynamic>?> _noOpLoader(Uri url) async {
  return Future.value(null);
}
