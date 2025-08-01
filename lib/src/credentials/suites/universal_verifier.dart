import '../../types.dart';
import '../models/parsed_vc.dart';
import '../proof/embedded_proof_suite.dart' show DocumentLoader;
import '../verification/vc_expiry_verifier.dart';
import '../verification/vc_integrity_verifier.dart';
import '../verification/vc_revocation_verifier.dart';
import '../verification/vc_verifier.dart';

/// Allows verification of any supported Verifiable Credential (VC) encodings.
///
/// Combines a default set of verifiers (like expiry and integrity checks)
/// and optional custom verifiers.
///
/// Supports custom document loaders for loading external resources during verification.
/// This is useful for implementing custom caching strategies or for loading resources
/// from non-standard locations.
final class UniversalVerifier {
  /// List of custom verifiers provided during construction.
  final List<VcVerifier> customVerifiers;

  /// Default verifiers always run during verification.
  ///
  /// Includes:
  /// - [VcExpiryVerifier]: Validates the credential's expiration time.
  /// - [VcIntegrityVerifier]: Validates the cryptographic integrity of the credential.
  final List<VcVerifier> defaultVerifiers;

  /// Custom document loader for loading external resources during verification.
  ///
  /// This loader is used by the [VcIntegrityVerifier] to load external resources
  /// like JSON-LD contexts and DID documents during verification.
  ///
  /// If not provided, a default no-op loader is used, which always returns null.
  final DocumentLoader? customDocumentLoader;

  /// Private constructor for [UniversalVerifier].
  ///
  /// Used by factory constructors to create instances with specific configurations.
  UniversalVerifier._({
    required this.defaultVerifiers,
    required this.customVerifiers,
    this.customDocumentLoader,
  });

  /// Creates a [UniversalVerifier].
  ///
  /// Optionally accepts:
  /// - [customVerifiers]: Additional verifiers to run after the defaults.
  /// - [customDocumentLoader]: Custom document loader for loading external resources
  ///   during verification. This is useful for implementing custom caching strategies
  ///   or for loading resources from non-standard locations.
  ///
  /// Example:
  /// ```dart
  /// // Define a custom document loader
  /// Future<Map<String, dynamic>?> myDocumentLoader(Uri url) async {
  ///   // Custom logic to load documents
  ///   // ...
  ///   return document;
  /// }
  ///
  /// // Create a verifier with the custom document loader
  /// final verifier = UniversalVerifier(
  ///   customDocumentLoader: myDocumentLoader,
  /// );
  ///
  /// // Verify a credential
  /// final result = await verifier.verify(credential);
  /// ```
  factory UniversalVerifier({
    List<VcVerifier>? customVerifiers,
    DocumentLoader? customDocumentLoader,
  }) {
    final defaultVerifiers = <VcVerifier>[
      VcExpiryVerifier(),
      VcIntegrityVerifier(customDocumentLoader: customDocumentLoader),
      RevocationList2020Verifier(customDocumentLoader: customDocumentLoader),
    ];

    return UniversalVerifier._(
      defaultVerifiers: List.unmodifiable(defaultVerifiers),
      customVerifiers: customVerifiers ?? [],
      customDocumentLoader: customDocumentLoader,
    );
  }

  /// Creates a [UniversalVerifier] with cached verifier instances.
  ///
  /// This factory method can be used to create a verifier that reuses the same
  /// verifier instances across multiple verifications, which can be more efficient.
  ///
  /// In the current implementation, this method behaves the same as the default
  /// constructor, but in future versions it may implement more sophisticated
  /// caching strategies.
  ///
  /// Optionally accepts:
  /// - [customVerifiers]: Additional verifiers to run after the defaults.
  /// - [customDocumentLoader]: Custom document loader for loading external resources.
  ///
  /// Example:
  /// ```dart
  /// // Create a verifier with cached verifiers
  /// final verifier = UniversalVerifier.createWithCachedVerifiers(
  ///   customDocumentLoader: myCustomDocumentLoader,
  /// );
  ///
  /// // Verify multiple credentials efficiently
  /// final result1 = await verifier.verify(credential1);
  /// final result2 = await verifier.verify(credential2);
  /// ```
  static UniversalVerifier createWithCachedVerifiers({
    List<VcVerifier>? customVerifiers,
    DocumentLoader? customDocumentLoader,
  }) {
    // This is a simple implementation that doesn't actually cache anything yet.
    // In a future version, this could maintain a cache of verifier instances.
    return UniversalVerifier(
      customVerifiers: customVerifiers,
      customDocumentLoader: customDocumentLoader,
    );
  }

  /// Verifies the provided [data] using both default and custom verifiers.
  ///
  /// Aggregates all errors and warnings found during verification.
  ///
  /// Returns a [VerificationResult] summarizing the findings.
  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final errors = <String>[];
    final warnings = <String>[];

    for (final verifier in defaultVerifiers) {
      final result = await verifier.verify(data);
      errors.addAll(result.errors);
      warnings.addAll(result.warnings);
    }

    for (final customVerifier in customVerifiers) {
      var verifResult = await customVerifier.verify(data);
      errors.addAll(verifResult.errors);
      warnings.addAll(verifResult.warnings);
    }

    return VerificationResult.fromFindings(
      errors: errors,
      warnings: warnings,
    );
  }
}
