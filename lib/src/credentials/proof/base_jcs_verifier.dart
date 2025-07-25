import 'dart:typed_data';

import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_verifier.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import 'base_data_integrity_verifier.dart';
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
  /// [issuerDid]: The expected issuer DID.
  /// [getNow]: Optional time supplier (defaults to `DateTime.now`).
  /// [domain]: Optional expected domain(s).
  /// [challenge]: Optional expected challenge string.
  BaseJcsVerifier({
    required super.issuerDid,
    super.getNow,
    super.domain,
    super.challenge,
    super.customDocumentLoader,
  });

  @override
  String get expectedProofType => JcsUtils.dataIntegrityType;

  @override
  String get expectedCryptosuite => expectedJcsCryptosuite;

  @override
  String get contextUrl => 'https://w3id.org/security/data-integrity/v1';

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
    final expectedScheme = cryptosuiteToScheme[expectedJcsCryptosuite];
    if (expectedScheme == null) {
      throw SsiException(
        message:
            'Unknown cryptosuite: $expectedJcsCryptosuite, cannot determine signature scheme.',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
    return expectedScheme;
  }
}
