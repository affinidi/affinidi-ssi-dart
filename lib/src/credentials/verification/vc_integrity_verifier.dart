import '../../did/did_resolver.dart';
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

  /// Custom DID resolver for resolving DID documents during verification.
  ///
  /// If not provided, the default universal DID resolver is used.
  final DidResolver? didResolver;

  /// Creates a [VcIntegrityVerifier].
  ///
  /// Optionally accepts:
  /// - [customDocumentLoader] to use when loading external resources during verification.
  ///   This is useful for implementing custom caching strategies or for loading resources
  ///   from non-standard locations.
  /// - [didResolver] to use for custom DID resolution logic.
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
  ///   didResolver: myCustomDidResolver,
  /// );
  ///
  /// // Verify a credential
  /// final result = await verifier.verify(credential);
  /// ```
  VcIntegrityVerifier({
    this.customDocumentLoader,
    this.didResolver,
  });

  /// Verifies the signature and cryptographic integrity of the [data] credential.
  ///
  /// Returns a [VerificationResult] indicating success or reporting a failed
  /// integrity verification error.
  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential data) async {
    final vcSuite = VcSuites.getVcSuiteWithOptions(
      data,
      customDocumentLoader: customDocumentLoader,
      didResolver: didResolver,
    );

    var integrityValid = false;

    try {
      integrityValid =
          await vcSuite.verifyIntegrity(data, didResolver: didResolver);
    } catch (e) {
      integrityValid = false;
    }

    if (!integrityValid) {
      return Future.value(
        VerificationResult.invalid(
          errors: [
            '${SsiExceptionType.failedIntegrityVerification.code} for VC id: ${data.id}',
          ],
        ),
      );
    }

    return Future.value(
      VerificationResult.ok(),
    );
  }
}
