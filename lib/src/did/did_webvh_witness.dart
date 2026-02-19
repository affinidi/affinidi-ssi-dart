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

/// Verifier for DID:WebVH witness proofs per the v1.0 specification.
///
/// Features:
/// - Validates `eddsa-jcs-2022` cryptosuite with `assertionMethod` purpose
/// - Enforces `did:key` format for witness DIDs
/// - Implements "later proofs" rule: proof for versionId N satisfies entries 1-N///
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
  /// Steps:
  /// 1. Extracts threshold and authorized witness DIDs from config
  /// 2. Collects applicable proofs using "later proofs" rule
  /// 3. Validates each proof (cryptosuite, purpose, witness authorization)
  /// 4. Verifies proof signatures using DataIntegrityEddsaJcsVerifier
  /// 5. Returns success if valid proofs meet or exceed threshold
  ///
  /// Optimization: Exits early once threshold is satisfied.
  Future<WitnessVerificationResult> verify({
    required DidWebVhLogEntry entry,
    required List<DidWebVhWitness> witnessProofs,
    required Map<String, dynamic> witnessConfig,
  }) async {
    final threshold = witnessConfig['threshold'] as int? ?? 0;
    final witnessesArray = witnessConfig['witnesses'] as List<dynamic>? ?? [];
    final authorizedWitnessDids = witnessesArray
        .map((w) => (w as Map<String, dynamic>)['id'] as String)
        .toSet();

    // Validate threshold is not negative
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

    int validCount = 0;
    final validWitnessDids = <String>{};
    final entryVersionNumber = entry.versionNumber;
    final applicableProofs = <_ProofWithVersionId>[];

    // "Later proofs" rule: proof for versionId N can satisfy entries 1-N
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

    for (final proofWithVersion in applicableProofs) {
      final proofMap = proofWithVersion.proof;

      if (proofMap['cryptosuite'] != 'eddsa-jcs-2022') {
        continue;
      }
      if (proofMap['proofPurpose'] != 'assertionMethod') {
        continue;
      }

      final verificationMethod = proofMap['verificationMethod'] as String?;
      if (verificationMethod == null) {
        continue;
      }

      final witnessDid = verificationMethod.split('#').first;
      if (!witnessDid.startsWith('did:key:')) {
        continue;
      }
      if (!authorizedWitnessDids.contains(witnessDid)) {
        continue;
      }
      if (validWitnessDids.contains(witnessDid)) {
        continue;
      }

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
        continue; // Ignore proofs that fail verification
      }

      // Early exit optimization: stop once we have enough valid proofs
      if (validCount >= threshold) {
        break;
      }
    }

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
  /// IMPORTANT: Creates a deep copy of the proof map because
  /// [DataIntegrityEddsaJcsVerifier.verify] modifies the proof in-place
  /// by extracting and removing the 'proofValue' field during verification.
  ///
  /// This prevents the original proof from being mutated, which would cause
  /// subsequent verification attempts to fail.
  ///
  /// Returns `true` if the signature is valid, `false` otherwise.
  Future<bool> _verifyProofSignature({
    required String signedVersionId,
    required Map<String, dynamic> proofMap,
    required String witnessDid,
  }) async {
    try {
      // CRITICAL: Must deep copy to prevent mutation by the verifier
      final proofMapCopy = Map<String, dynamic>.from(proofMap);
      final documentToVerify = {
        'versionId': signedVersionId,
        'proof': proofMapCopy
      };
      final verifier = DataIntegrityEddsaJcsVerifier(
        verifierDid: witnessDid,
      );

      final result = await verifier.verify(documentToVerify);
      return result.isValid;
    } catch (e) {
      return false;
    }
  }

  /// Parses version number from versionId (format: "N-QmHash...").
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

  /// Fetches witness data for a DID from the well-known witness URI.
  static Future<List<DidWebVhWitness>> fetchWitnesses(DidWebVh did,
      [http.Client? client]) async {
    final witnessUrl = did.witnessUrl;

    try {
      final data = await downloadDocument(
        Uri.parse(witnessUrl),
        client: client,
      );

      final json = jsonDecode(data);

      if (json is! List) {
        throw SsiException(
          message:
              'Invalid DIDWebVH Witness JSON: expected array, got ${json.runtimeType}',
          code: SsiExceptionType.invalidDidWebVh.code,
        );
      }

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

class _ProofWithVersionId {
  final Map<String, dynamic> proof;
  final String signedVersionId;

  _ProofWithVersionId({
    required this.proof,
    required this.signedVersionId,
  });
}
