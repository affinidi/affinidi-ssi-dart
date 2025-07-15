import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../models/parsed_vc.dart';
import '../proof/embedded_proof_suite.dart' show DocumentLoader;
import '../suites/vc_suites.dart';
import 'vc_verifier.dart';

/// Verifier that checks the cryptographic integrity of a Verifiable Credential (VC).
///
/// It delegates the integrity verification to the appropriate VC suite
/// based on the input credentials.
///
/// Supports custom document loaders for loading external resources during verification.
/// This is useful for implementing custom caching strategies or for loading resources
/// from non-standard locations.
class VcIntegrityVerifier implements VcVerifier {
  /// Custom document loader for loading external resources during verification.
  ///
  /// This loader is used to load external resources like JSON-LD contexts and
  /// DID documents during verification.
  ///
  /// If not provided, a default no-op loader is used, which always returns null.
  final DocumentLoader? customDocumentLoader;

  /// Creates a [VcIntegrityVerifier].
  ///
  /// Optionally accepts a [customDocumentLoader] to use when loading external resources
  /// during verification. This is useful for implementing custom caching strategies
  /// or for loading resources from non-standard locations.
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
  /// final verifier = VcIntegrityVerifier(
  ///   customDocumentLoader: myDocumentLoader,
  /// );
  ///
  /// // Verify a credential
  /// final result = await verifier.verify(credential);
  /// ```
  VcIntegrityVerifier({
    this.customDocumentLoader,
  });

  /// Verifies the signature and cryptographic integrity of the [data] credential.
  ///
  /// Returns a [VerificationResult] indicating success or reporting a failed
  /// integrity verification error.
  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final vcSuite =
        VcSuites.getVcSuiteWithDocumentLoader(data, customDocumentLoader);

    var integrityValid = false;

    try {
      integrityValid = await vcSuite.verifyIntegrity(data);
    } catch (e) {
      integrityValid = false;
    }

    if (!integrityValid) {
      return Future.value(
        VerificationResult.invalid(
          errors: [SsiExceptionType.failedIntegrityVerification.code],
        ),
      );
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
