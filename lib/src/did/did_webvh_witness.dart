import 'dart:convert';

import 'package:http/http.dart' as http;

import '../../ssi.dart';
import 'did_webvh.dart';

/// Result of witness verification for a DID:WebVH log entry.
class WitnessVerificationResult {
  /// Indicates if the witness proofs meet the threshold requirement.
  final bool isValid;

  /// The number of valid witness proofs found.
  final int validCount;

  /// The required number of valid proofs for successful verification.
  final int threshold;

  /// The set of witness DIDs that provided valid proofs.
  final Set<String> validWitnessDids;

  /// Contains an error message if verification failed (e.g., insufficient valid proofs).
  final String? error;

  /// Constructs a [WitnessVerificationResult] with the given parameters.
  WitnessVerificationResult({
    required this.isValid,
    required this.validCount,
    required this.threshold,
    required this.validWitnessDids,
    this.error,
  });

  /// Creates a successful verification result.
  factory WitnessVerificationResult.success({
    required int validCount,
    required int threshold,
    required Set<String> validWitnessDids,
  }) {
    return WitnessVerificationResult(
      isValid: true,
      validCount: validCount,
      threshold: threshold,
      validWitnessDids: validWitnessDids,
    );
  }

  /// Creates a failed verification result with an error message.
  factory WitnessVerificationResult.failure({
    required int validCount,
    required int threshold,
    required Set<String> validWitnessDids,
    required String error,
  }) {
    return WitnessVerificationResult(
      isValid: false,
      validCount: validCount,
      threshold: threshold,
      validWitnessDids: validWitnessDids,
      error: error,
    );
  }

  @override
  String toString() {
    return 'WitnessVerificationResult(isValid: $isValid, validCount: $validCount, '
        'threshold: $threshold, validWitnessDids: $validWitnessDids, error: $error)';
  }
}

/// Represents a single witness entry from the DID:WebVH witness JSON file.
class DidWebVhWitness {
  /// The versionId of the log entry this witness proof corresponds to.
  /// Format: "N-QmHash..." where N is the version number.
  final String versionId;

  /// The list of proofs provided by the witness for this log entry.
  /// Each proof must be a DataIntegrityProof with eddsa-jcs-2022 cryptosuite.
  final List<Map<String, dynamic>> proof;

  DidWebVhWitness._({
    required this.versionId,
    required this.proof,
  });

  /// Factory constructor to create a [DidWebVhWitness] from JSON data.
  /// Validates that required fields are present and correctly typed.
  factory DidWebVhWitness.fromJson(Map<String, dynamic> json) {
    if (json['versionId'] == null) {
      throw SsiException(
        message: 'Witness entry missing required "versionId" field',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }

    if (json['proof'] == null) {
      throw SsiException(
        message: 'Witness entry missing required "proof" field',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }

    return DidWebVhWitness._(
      versionId: json['versionId'] as String,
      proof: (json['proof'] as List<dynamic>)
          .map((e) => e as Map<String, dynamic>)
          .toList(),
    );
  }
}

/// Verifies DID:WebVH witness proofs per the v1.0 specification.
///
/// Core Features:
/// - Validates `eddsa-jcs-2022` cryptosuite with `assertionMethod` purpose
/// - Enforces `did:key` format for witness DIDs
/// - Implements "later proofs" rule: proof for versionId N satisfies entries 1-N
/// - Prevents duplicate witness counting (one proof per witness DID)
/// - Optimized early exit when threshold is satisfied
///
/// Example:
/// ```dart
/// final verifier = DidWebVhWitnessVerifier();
/// final witnesses = await DidWebVhWitnessVerifier.fetchWitnesses(did);
/// final result = await verifier.verify(
///   entry: logEntry,
///   witnessProofs: witnesses,
///   witnessConfig: {'threshold': 2, 'witnesses': [{'id': 'did:key:...'}, ...]},
/// );
/// ```
class DidWebVhWitnessVerifier {
  /// Verifies witness proofs for a log entry against the witness configuration.
  ///
  /// Verification Process:
  /// 1. Validates witness configuration (threshold must be non-negative)
  /// 2. Extracts threshold and authorized witness DIDs from config
  /// 3. Collects applicable proofs using "later proofs" rule
  /// 4. Validates each proof (cryptosuite, purpose, witness authorization)
  /// 5. Verifies cryptographic signatures using [DataIntegrityEddsaJcsVerifier]
  /// 6. Returns success if valid proofs meet or exceed threshold
  ///
  /// Throws [SsiException] if threshold is negative.
  ///
  /// Optimization: Exits early once threshold is satisfied.
  Future<WitnessVerificationResult> verify({
    required DidWebVhLogEntry entry,
    required List<DidWebVhWitness> witnessProofs,
    required Map<String, dynamic> witnessConfig,
  }) async {
    // Extract witness configuration
    final threshold = witnessConfig['threshold'] as int? ?? 0;
    final witnessesArray = witnessConfig['witnesses'] as List<dynamic>? ?? [];
    final authorizedWitnessDids = witnessesArray
        .map((w) => (w as Map<String, dynamic>)['id'] as String)
        .toSet();

    // Validate threshold
    if (threshold < 0) {
      throw SsiException(
        message: 'Invalid witness configuration: threshold cannot be negative (got $threshold)',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }

    // Fast path: if threshold is 0, automatically succeed
    if (threshold == 0) {
      return WitnessVerificationResult.success(
        validCount: 0,
        threshold: threshold,
        validWitnessDids: const {},
      );
    }

    // Fast path: if no authorized witnesses, cannot succeed
    if (authorizedWitnessDids.isEmpty) {
      return WitnessVerificationResult.failure(
        validCount: 0,
        threshold: threshold,
        validWitnessDids: const {},
        error: 'No authorized witnesses configured (witnesses array is empty)',
      );
    }

    // Initialize verification state
    int validCount = 0;
    final validWitnessDids = <String>{};
    final entryVersionNumber = entry.versionNumber;
    final applicableProofs = <_ProofWithVersionId>[];

    // Collect applicable proofs using "later proofs" rule:
    // A proof for versionId N can satisfy entries 1 through N
    for (final witnessEntry in witnessProofs) {
      final proofVersionNumber = _parseVersionNumber(witnessEntry.versionId);
      if (proofVersionNumber >= entryVersionNumber) {
        for (final proof in witnessEntry.proof) {
          applicableProofs.add(_ProofWithVersionId(
            proof: proof,
            signedVersionId: witnessEntry.versionId,
          ));
        }
      }
    }

    // Verify each applicable proof
    for (final proofWithVersion in applicableProofs) {
      final proofMap = proofWithVersion.proof;

      // Validate cryptosuite
      if (proofMap['cryptosuite'] != 'eddsa-jcs-2022') {
        continue;
      }

      // Validate proof purpose
      if (proofMap['proofPurpose'] != 'assertionMethod') {
        continue;
      }

      // Extract verification method
      final verificationMethod = proofMap['verificationMethod'] as String?;
      if (verificationMethod == null) {
        continue;
      }

      // Extract and validate witness DID
      final witnessDid = verificationMethod.split('#').first;
      if (!witnessDid.startsWith('did:key:')) {
        continue; // Only did:key witnesses are allowed
      }
      if (!authorizedWitnessDids.contains(witnessDid)) {
        continue; // Witness not authorized for this entry
      }
      if (validWitnessDids.contains(witnessDid)) {
        continue; // Already counted this witness (prevent duplicates)
      }

      // Verify cryptographic signature
      try {
        final isValid = await _verifyProofSignature(
          signedVersionId: proofWithVersion.signedVersionId,
          proofMap: proofMap,
          witnessDid: witnessDid,
        );

        if (isValid) {
          validCount++;
          validWitnessDids.add(witnessDid);
        }
      } catch (e) {
        // Ignore proofs that fail verification
        continue;
      }

      // Early exit: stop once threshold is satisfied
      if (validCount >= threshold) {
        break;
      }
    }

    // Determine verification result
    final isValid = validCount >= threshold;

    if (isValid) {
      return WitnessVerificationResult.success(
        validCount: validCount,
        threshold: threshold,
        validWitnessDids: validWitnessDids,
      );
    } else {
      return WitnessVerificationResult.failure(
        validCount: validCount,
        threshold: threshold,
        validWitnessDids: validWitnessDids,
        error: 'Insufficient witness proofs for versionId ${entry.versionId}. '
            'Required: $threshold, Valid: $validCount, '
            'Authorized witnesses: ${authorizedWitnessDids.length}',
      );
    }
  }

  /// Verifies the cryptographic signature of a witness proof.
  ///
  /// CRITICAL: This method creates a deep copy of [proofMap] before verification
  /// because [DataIntegrityEddsaJcsVerifier.verify] modifies the proof in-place
  /// by extracting and removing the `proofValue` field. Without the deep copy,
  /// the original proof would be mutated and subsequent verification attempts
  /// would fail.
  ///
  /// Returns `true` if the signature is valid, `false` otherwise (including
  /// when verification throws an exception).
  Future<bool> _verifyProofSignature({
    required String signedVersionId,
    required Map<String, dynamic> proofMap,
    required String witnessDid,
  }) async {
    try {
      // Create deep copy to prevent mutation
      final proofMapCopy = Map<String, dynamic>.from(proofMap);
      final documentToVerify = {
        'versionId': signedVersionId,
        'proof': proofMapCopy
      };

      // Verify signature using witness DID
      final verifier = DataIntegrityEddsaJcsVerifier(
        verifierDid: witnessDid,
      );

      final result = await verifier.verify(documentToVerify);
      return result.isValid;
    } catch (e) {
      // Treat exceptions as invalid signatures
      return false;
    }
  }

  /// Parses the version number from a versionId string.
  ///
  /// The versionId format is "N-QmHash..." where N is the version number.
  ///
  /// Throws [SsiException] if the format is invalid or N is not a valid integer.
  int _parseVersionNumber(String versionId) {
    final dashIndex = versionId.indexOf('-');
    if (dashIndex == -1) {
      throw SsiException(
        message: 'Invalid versionId format (missing dash): $versionId',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
    final numberPart = versionId.substring(0, dashIndex);
    try {
      return int.parse(numberPart);
    } on FormatException {
      throw SsiException(
        message:
            'Invalid version number in versionId (not an integer): $versionId',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Fetches witness proofs from the well-known witness URI.
  ///
  /// The witness file is located at:
  /// `https://<domain>/.well-known/did-webvh/<scid>/witness.json`
  ///
  /// Returns a list of [DidWebVhWitness] entries from the witness file.
  ///
  /// Throws [SsiException] if:
  /// - Network request fails
  /// - Response is not valid JSON
  /// - JSON is not an array
  /// - Witness entries are malformed
  static Future<List<DidWebVhWitness>> fetchWitnesses(DidWebVh did,
      [http.Client? client]) async {
    final witnessUrl = did.witnessUrl;

    try {
      // Download witness file
      final data = await downloadDocument(
        Uri.parse(witnessUrl),
        client: client,
      );

      // Parse JSON
      final json = jsonDecode(data);

      // Validate JSON structure
      if (json is! List) {
        throw SsiException(
          message:
              'Invalid DIDWebVH Witness JSON: expected array, got ${json.runtimeType}',
          code: SsiExceptionType.invalidDidWebVh.code,
        );
      }

      // Parse witness entries
      return json
          .map((e) => DidWebVhWitness.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (e) {
      if (e is SsiException) rethrow;
      throw SsiException(
        message: 'Failed to fetch DIDWebVH Witness from $witnessUrl: $e',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }
}

/// Internal helper class to associate a proof with the versionId it signed.
///
/// Used to implement the "later proofs" rule where a proof for versionId N
/// can satisfy verification for entries 1 through N.
class _ProofWithVersionId {
  /// The proof object from the witness entry.
  final Map<String, dynamic> proof;

  /// The versionId that this proof actually signed.
  final String signedVersionId;

  _ProofWithVersionId({
    required this.proof,
    required this.signedVersionId,
  });
}
