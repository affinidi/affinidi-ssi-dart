import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';

import '../../digest_utils.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../util/jcs_util.dart';

/// Utilities for JSON Canonicalization Scheme (JCS) cryptosuites.
///
/// Provides common functionality for ecdsa-jcs-2019 and eddsa-jcs-2022
/// cryptosuites to eliminate code duplication and ensure consistency.
class JcsUtils {
  /// Private constructor to prevent instantiation.
  JcsUtils._();

  /// Data Integrity proof type constant.
  static const String dataIntegrityType = 'DataIntegrityProof';

  /// Validates proof configuration structure and required fields.
  ///
  /// Ensures the proof has the correct type and cryptosuite values,
  /// and validates datetime field formats if present.
  ///
  /// Throws [SsiException] if validation fails.
  static void validateProofConfiguration(
    Map<String, dynamic> proofConfig,
    String expectedCryptosuite,
  ) {
    // Ensure required type and cryptosuite values
    if (proofConfig['type'] != dataIntegrityType ||
        proofConfig['cryptosuite'] != expectedCryptosuite) {
      throw SsiException(
        message:
            'Invalid proof configuration: type must be "$dataIntegrityType" and cryptosuite must be "$expectedCryptosuite"',
        code: SsiExceptionType.unableToParseVerifiableCredential.code,
      );
    }

    // Validate created field format if present
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

    // Validate expires field format if present
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

  /// Computes Data Integrity hash using JCS canonicalization.
  ///
  /// Canonicalizes both the proof and document using JCS, then computes
  /// hashes using the specified algorithm and concatenates them.
  ///
  /// [proof] The proof configuration object
  /// [unsignedCredential] The unsigned credential/document
  /// [hashingAlgorithm] The hashing algorithm to use
  ///
  /// Returns the concatenated hash bytes (proofHash + documentHash).
  static Future<Uint8List> computeDataIntegrityJcsHash(
    Map<String, dynamic> proof,
    Map<String, dynamic> unsignedCredential,
    HashingAlgorithm hashingAlgorithm,
  ) async {
    final canonicalProof = JcsUtil.canonicalize(proof);
    final proofConfigHash = DigestUtils.getDigest(
      utf8.encode(canonicalProof),
      hashingAlgorithm: hashingAlgorithm,
    );

    final canonicalDocument = JcsUtil.canonicalize(unsignedCredential);
    final transformedDocumentHash = DigestUtils.getDigest(
      utf8.encode(canonicalDocument),
      hashingAlgorithm: hashingAlgorithm,
    );

    return Uint8List.fromList(proofConfigHash + transformedDocumentHash);
  }

  /// Encodes a signature using the appropriate encoding for JCS cryptosuites.
  ///
  /// JCS cryptosuites use base58-btc multibase encoding (z prefix).
  ///
  /// [signature] The raw signature bytes
  ///
  /// Returns the encoded signature string with 'z' prefix.
  static String encodeJcsSignature(Uint8List signature) {
    return 'z${base58BitcoinEncode(signature)}';
  }

  /// Decodes a signature from JCS cryptosuite encoding.
  ///
  /// Validates that the signature uses base58-btc multibase encoding
  /// and decodes it to raw bytes.
  ///
  /// [proofValue] The encoded signature value
  /// [cryptosuite] The cryptosuite name for error messages
  ///
  /// Returns the decoded signature bytes.
  ///
  /// Throws [SsiException] if encoding is invalid.
  static Uint8List decodeJcsSignature(String proofValue, String cryptosuite) {
    if (!proofValue.startsWith('z')) {
      throw SsiException(
        message:
            'JCS cryptosuite $cryptosuite requires base58-btc multibase encoding (z prefix)',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }
    return base58BitcoinDecode(proofValue.substring(1));
  }

  /// Creates a base proof configuration structure for JCS cryptosuites.
  ///
  /// Builds the common proof structure with required fields and optionally
  /// includes additional fields if they have values.
  ///
  /// [cryptosuite] The cryptosuite identifier
  /// [created] The creation timestamp
  /// [verificationMethod] The verification method identifier
  /// [proofPurpose] The proof purpose (optional)
  /// [expires] The expiration timestamp (optional)
  /// [challenge] The challenge value (optional)
  /// [domain] The domain values (optional)
  ///
  /// Returns the proof configuration map.
  static Map<String, dynamic> createBaseProofConfiguration({
    required String cryptosuite,
    required DateTime created,
    required String verificationMethod,
    String? proofPurpose,
    DateTime? expires,
    String? challenge,
    List<String>? domain,
  }) {
    final proof = <String, dynamic>{
      'type': dataIntegrityType,
      'cryptosuite': cryptosuite,
      'created': created.toIso8601String(),
      'verificationMethod': verificationMethod,
      'proofPurpose': proofPurpose,
    };

    // Only add optional fields if they have values
    if (expires != null) {
      proof['expires'] = expires.toIso8601String();
    }
    if (challenge != null) {
      proof['challenge'] = challenge;
    }
    if (domain != null) {
      proof['domain'] = domain;
    }

    return proof;
  }

  /// Prepares a proof for verification by setting the appropriate context.
  ///
  /// For JCS cryptosuites, the proof context should match the document context
  /// during verification to ensure proper canonicalization.
  ///
  /// [proof] The proof configuration
  /// [documentContext] The document's @context value
  ///
  /// Returns a copy of the proof with the document context set.
  static Map<String, dynamic> prepareProofForVerification(
    Map<String, dynamic> proof,
    dynamic documentContext,
  ) {
    final proofCopy = Map<String, dynamic>.from(proof);

    // Set proof context to document context if present
    if (documentContext != null) {
      proofCopy['@context'] = documentContext;
    }

    return proofCopy;
  }

  /// Checks if a cryptosuite identifier represents a JCS cryptosuite.
  ///
  /// [cryptosuite] The cryptosuite identifier to check
  ///
  /// Returns true if the cryptosuite uses JCS canonicalization.
  static bool isJcsCryptosuite(String cryptosuite) {
    return cryptosuite.endsWith('-jcs-2019') ||
        cryptosuite.endsWith('-jcs-2022');
  }

  /// Gets the appropriate hashing algorithm for a signature scheme.
  ///
  /// [signatureScheme] The signature scheme
  ///
  /// Returns the corresponding hashing algorithm.
  static HashingAlgorithm getHashingAlgorithmForScheme(
    SignatureScheme signatureScheme,
  ) {
    return signatureScheme.hashingAlgorithm;
  }
}
