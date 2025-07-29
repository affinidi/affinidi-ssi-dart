import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_verifier.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import 'base_data_integrity_verifier.dart';
import 'embedded_proof_suite.dart';
import 'jcs_utils.dart';

/// Base class for Data Integrity proof verifiers using JCS canonicalization.
///
/// Provides common functionality for JCS-based cryptosuites like ecdsa-jcs-2019
/// and eddsa-jcs-2022, eliminating code duplication and ensuring consistency.
abstract class BaseJcsVerifier extends BaseDataIntegrityVerifier {
  /// The expected cryptosuite identifier for this verifier.
  String get expectedJcsCryptosuite;

  /// The hashing algorithm to use for this cryptosuite.
  HashingAlgorithm get hashingAlgorithm;

  /// Constructs a new [BaseJcsVerifier].
  ///
  /// [verifierDid]: The DID of the issuer whose credential this verifier will validate.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  BaseJcsVerifier({
    required String verifierDid,
    DateTime Function()? getNow,
    super.domain,
    super.challenge,
    DocumentLoader? customDocumentLoader,
  }) : super(
          issuerDid: verifierDid,
          getNow: getNow ?? DateTime.now,
          customDocumentLoader: customDocumentLoader ?? (uri) async => null,
        );

  @override
  String get expectedProofType => JcsUtils.dataIntegrityType;

  @override
  String get expectedCryptosuite => expectedJcsCryptosuite;

  @override
  String get contextUrl => 'https://w3id.org/security/data-integrity/v2';

  @override
  String get proofValueField => 'proofValue';

  @override
  Future<Uint8List> computeSignatureHash(
    Map<String, dynamic> proof,
    Map<String, dynamic> unsignedCredential,
    Future<RemoteDocument?> Function(Uri url, LoadDocumentOptions? options)
        documentLoader,
  ) async {
    return JcsUtils.computeDataIntegrityJcsHash(
      proof,
      unsignedCredential,
      hashingAlgorithm,
    );
  }

  @override
  Future<bool> verifySignature(
    String proofValue,
    String issuerDid,
    Uri verificationMethod,
    Uint8List hash,
  ) async {
    // Decode JCS signature
    final signature =
        JcsUtils.decodeJcsSignature(proofValue, expectedJcsCryptosuite);

    // Get signature scheme (may be static or dynamic depending on cryptosuite)
    final signatureScheme = await getSignatureScheme(verificationMethod);

    // Create verifier and verify signature
    final verifier = await DidVerifier.create(
      algorithm: signatureScheme,
      kid: verificationMethod.toString(),
      issuerDid: issuerDid,
    );
    return verifier.verify(hash, signature);
  }

  /// Gets the signature scheme for signature verification.
  ///
  /// Subclasses can override this to provide static or dynamic scheme detection.
  /// The default implementation uses the static cryptosuite-to-scheme mapping.
  Future<SignatureScheme> getSignatureScheme(Uri verificationMethod) async {
    final expectedSchemes = cryptosuiteToScheme[expectedJcsCryptosuite];
    if (expectedSchemes == null || expectedSchemes.isEmpty) {
      throw SsiException(
        message:
            'Unknown cryptosuite: $expectedJcsCryptosuite, cannot determine signature scheme.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }

    // For single-scheme cryptosuites, return the only scheme
    if (expectedSchemes.length == 1) {
      return expectedSchemes.first;
    }

    // For multi-scheme cryptosuites, this method should be overridden by subclasses
    // to determine the scheme dynamically from the verification method
    throw SsiException(
      message:
          'Cryptosuite $expectedJcsCryptosuite supports multiple signature schemes. Override getSignatureScheme to determine the correct scheme.',
      code: SsiExceptionType.unsupportedSignatureScheme.code,
    );
  }

  @override
  Future<VerificationResult> validateCryptosuite(
      Map<String, dynamic> document, Map<String, dynamic> proof) async {
    return _validateJcsContext(document, proof);
  }

  @override
  Map<String, dynamic> prepareProofForVerification(
      Map<String, dynamic> proof, Map<String, dynamic> document) {
    final proofCopy = Map<String, dynamic>.from(proof);

    // Use document context in proof for JCS cryptosuites during verification
    final documentContext = document['@context'];
    if (documentContext != null) {
      proofCopy['@context'] = documentContext;
    }

    return proofCopy;
  }

  /// Validates context for JCS cryptosuites according to W3C Data Integrity specification.
  ///
  /// Per the W3C VC Data Integrity ECDSA specification:
  /// "The document context must include all proof context entries at the beginning in the same order"
  /// Reference: https://www.w3.org/TR/vc-di-ecdsa/#verify-proof-ecdsa-jcs-2019
  VerificationResult _validateJcsContext(
      Map<String, dynamic> document, Map<String, dynamic> proof) {
    final proofContext = proof['@context'];
    if (proofContext != null) {
      final documentContext = document['@context'];
      if (!_contextStartsWith(documentContext, proofContext)) {
        return VerificationResult.invalid(
          errors: [
            'Document @context must include all proof @context entries at the beginning in the same order'
          ],
        );
      }
    }
    return VerificationResult.ok();
  }

  /// Checks if document context starts with proof context values in order.
  /// Required for JCS cryptosuite context validation.
  bool _contextStartsWith(dynamic documentContext, dynamic proofContext) {
    // Convert both contexts to lists for comparison
    final List<dynamic> docList = _contextToList(documentContext);
    final List<dynamic> proofList = _contextToList(proofContext);

    // Check if document context starts with proof context values
    if (proofList.length > docList.length) return false;

    for (int i = 0; i < proofList.length; i++) {
      if (docList[i] != proofList[i]) return false;
    }

    return true;
  }

  /// Converts a context value to normalized list format for comparison.
  List<dynamic> _contextToList(dynamic context) {
    if (context is List) {
      return context;
    } else if (context is String) {
      return [context];
    } else if (context is Map) {
      return [context];
    } else {
      return [];
    }
  }
}
