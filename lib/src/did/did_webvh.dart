import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:http/http.dart' as http;
import 'package:intl/intl.dart';

import '../../ssi.dart';
import '../digest_utils.dart';
import 'did.dart';

/// Parameters for a DID WebVH log entry that control DID processing and verification.
///
/// All log entries contain this JSON object defining the DID processing parameters
/// used by the DID Controller when publishing the current and subsequent log entries.
/// DID Resolvers must use the same parameters to process the DID Log to resolve the DID.
class DidWebVhLogEntryParameters {
  /// Specifies the did:webvh semver specification version to be used for processing the DID's log.
  ///
  /// Each version defines permitted cryptographic algorithms for log entries.
  /// - MUST appear in the first log entry
  /// - If not present in later entries, the previous value continues to apply
  /// - MAY appear in later entries to upgrade to a new specification version
  /// - MUST be set to a version equal to or higher than the currently active method
  /// - Acceptable values: "did:webvh:1.0" (permits SHA-256 hash, eddsa-jcs-2022 cryptosuite)
  final String? method;

  /// The Self-Certifying Identifier (SCID) value for the DID.
  ///
  /// The SCID is a hash of the DID's inception event.
  /// - MUST appear in the first log entry
  /// - MUST NOT appear in later log entries
  final String? scid;

  /// array of multikey-formatted public keys authorized to sign log entries that update the DID.
  ///
  /// These keys are authorized to control (create, update, deactivate) the DID.
  /// - MUST appear in the first log entry
  /// - MAY appear in subsequent entries to rotate keys
  /// - If not present in later entries, the previous value continues to apply
  /// - A key from the active updateKeys array MUST be used to authorize each log entry
  /// - SHOULD be set to empty array [] when deactivating the DID
  final List<String>? updateKeys;

  /// array of hashes of multikey-formatted public keys for pre-rotation.
  ///
  /// These are hashes of keys that MAY be added to the updateKeys list in the next log entry.
  /// At least one entry from nextKeyHashes MUST be added to the next updateKeys list.
  /// - Defaults to empty array [] if not set in the first log entry
  /// - If not set in other entries, value is retained from most recent prior value
  /// - Once set to non-empty array, pre-rotation is active
  /// - While active, nextKeyHashes and updateKeys MUST be present in all log entries
  /// - While active, all multikey public keys in new updateKeys MUST have their hashes
  ///   listed in the previous entry's nextKeyHashes
  /// - MAY be set to empty array [] to deactivate pre-rotation
  final List<String>? nextKeyHashes;

  /// object declaring the set of witnesses and threshold for DID updates.
  ///
  /// Contains "threshold" (integer) and "witnesses" (array) for witness approval process.
  /// - Defaults to {} (empty object) if not set in the first log entry
  /// - If not set in other entries, value is retained from most recent prior value
  /// - If updated from {}, the change is immediately active and the entry MUST be witnessed
  /// - MAY be set to {} to indicate witnesses are not (or no longer) being used
  /// - If witnesses are active when set to {}, that log entry MUST be witnessed
  final Map<String, dynamic>? witness;

  /// array of watcher URLs that monitor and cache the DID's state.
  ///
  /// Contains URLs of watchers that have agreed to monitor the DID.
  /// - Defaults to [] if not set in the first log entry
  /// - If not set in other entries, value is retained from most recent prior value
  /// - MAY be set to empty array [] to indicate watchers are not (or no longer) being used
  final List<String>? watchers;

  /// Boolean indicating if the DID is portable, allowing it to be moved while retaining SCID and history.
  ///
  /// Controls if a DID Controller can move the DID to a different location.
  /// - Can ONLY be set to true in the first entry
  /// - Defaults to false if omitted in the first entry
  /// - Retains value if omitted in later entries
  /// - Once set to false, MUST NOT be changed to true
  final bool? portable;

  /// Boolean indicating whether the DID has been deactivated.
  ///
  /// A deactivated DID is no longer subject to updates but remains resolvable.
  /// - Defaults to false if not set in the first log entry
  /// - If set to true, the DID is considered deactivated and no further updates are permitted
  final bool? deactivated;

  /// Unsigned integer indicating cache duration in seconds (time-to-live).
  ///
  /// Provides guidance from the DID Controller on how long resolvers should cache the resolved DID.
  /// Analogous to the TTL parameter used in DNS. Range: 0 to 2^31.
  /// - Defaults to 3600 (1 hour) if not set in the first log entry
  /// - If set to 0, indicates that the DID should not be cached
  final int? ttl;

  DidWebVhLogEntryParameters({
    this.method,
    this.scid,
    this.updateKeys,
    this.nextKeyHashes,
    this.witness,
    this.watchers,
    this.portable,
    this.deactivated,
    this.ttl,
  });

  factory DidWebVhLogEntryParameters.fromJson(Map<String, dynamic> json) {
    return DidWebVhLogEntryParameters(
      method: json['method'] as String?,
      scid: json['scid'] as String?,
      updateKeys: (json['updateKeys'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      nextKeyHashes: (json['nextKeyHashes'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      witness: json['witness'] as Map<String, dynamic>?,
      watchers: (json['watchers'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      portable: json['portable'] as bool?,
      deactivated: json['deactivated'] as bool?,
      ttl: json['ttl'] as int?,
    );
  }
}

/// A single entry in a DID WebVH log file.
///
/// Each entry represents a version of the DID and consists of:
/// - versionId: version number, dash, and entryHash
/// - versionTime: UTC timestamp in ISO8601 format
/// - parameters: DID processing configuration settings
/// - state: the DIDDoc for this version
/// - proof: Data Integrity proof(s) for the entry
class DidWebVhLogEntry {
  /// Version identifier in format: "{versionNumber}-{entryHash}"
  ///
  /// The version number starts at 1 and increments by one per version.
  /// The entryHash is calculated across the log entry content.
  final String versionId;

  /// UTC timestamp in ISO8601 format (e.g., "2024-04-05T07:32:58Z")
  ///
  /// The time MUST be before or equal to when the DID will be retrieved.
  /// MUST be greater than the previous entry's time.
  final DateTime versionTime;

  /// DID processing parameters that control generation and verification.
  ///
  /// Contains configuration options set by the DID Controller for processing
  /// current and future log entries.
  final DidWebVhLogEntryParameters parameters;

  /// The DID Document for this version of the DID.
  ///
  /// Contains the complete DID Document state including verificationMethod,
  /// authentication, service endpoints, etc.
  final DidDocument state;

  /// Data Integrity proof(s) created for the entry.
  ///
  /// Signed by a key authorized to update the DIDDoc.
  /// Must use proofPurpose set to "assertionMethod".
  final List<Map<String, dynamic>> proof;

  DidWebVhLogEntry({
    required this.versionId,
    required this.versionTime,
    required this.parameters,
    required this.state,
    required this.proof,
  });

  /// Creates a [DidWebVhLogEntry] from a JSON object.
  ///
  /// Parses the JSON representation of a log entry and converts it into
  /// a structured [DidWebVhLogEntry] object. This factory handles:
  /// - Parsing nested parameters object
  /// - Converting state to a [DidDocument]
  /// - Converting proof array to typed list
  ///
  /// Throws [TypeError] if required fields are missing or have incorrect types.
  factory DidWebVhLogEntry.fromJson(Map<String, dynamic> json) {
    final entryVersionId = json['versionId'] as String;
    final entryVersionIdParts = entryVersionId.split('-');
    late DateTime entryVersionTime;
    if (entryVersionIdParts.length != 2 ||
        int.tryParse(entryVersionIdParts[0]) == null ||
        entryVersionIdParts[1].isEmpty) {
      throw SsiDidResolutionException(
          message:
              'DID WebVh Log Entry versionId must start with a number, have a dash and a entry hash part',
          code: SsiExceptionType.invalidDidWebVh.code,
          resolutionMetadata: {
            'error': 'invalidDid',
            'message':
                'DID WebVh Log Entry versionId must start with a number, have a dash and a entry hash part',
          });
    }
    try {
      entryVersionTime = DateFormat('yyyy-MM-ddTHH:mm:ss\'Z\'')
          .parseUTC(json['versionTime'] as String);
    } on FormatException catch (e) {
      throw SsiDidResolutionException(
          message:
              'Invalid DID WebVh Log Entry versionTime format. versionTime must be in ISO8601 format (e.g., "2024-04-05T07:32:58Z") in entry with versionId $entryVersionId',
          code: SsiExceptionType.invalidDidWebVh.code,
          originalMessage: e.message,
          resolutionMetadata: {
            'error': 'invalidDid',
            'message':
                'Invalid DID WebVh Log Entry versionTime format. versionTime must be in ISO8601 format (e.g., "2024-04-05T07:32:58Z") in entry with versionId $entryVersionId',
          });
    }

    return DidWebVhLogEntry(
      versionId: entryVersionId,
      versionTime: entryVersionTime,
      parameters: DidWebVhLogEntryParameters.fromJson(
          Map<String, dynamic>.from(json['parameters'] as Map)),
      state: DidDocument.fromJson(json['state'] as Map<String, dynamic>),
      proof: (json['proof'] as List)
          .map((e) => e as Map<String, dynamic>)
          .toList(),
    );
  }

  Map<String, Object> _buildMapFromEntryWithVersionIdAndStrippedProof(
      String newVersionId) {
    return {
      'versionId': newVersionId,
      'versionTime': DateFormat('yyyy-MM-ddTHH:mm:ss\'Z\'').format(versionTime),
      'parameters': {
        if (parameters.method != null) 'method': parameters.method!,
        if (parameters.scid != null) 'scid': parameters.scid!,
        if (parameters.updateKeys != null) 'updateKeys': parameters.updateKeys!,
        if (parameters.nextKeyHashes != null)
          'nextKeyHashes': parameters.nextKeyHashes!,
        if (parameters.witness != null) 'witness': parameters.witness!,
        if (parameters.watchers != null) 'watchers': parameters.watchers!,
        if (parameters.portable != null) 'portable': parameters.portable!,
        if (parameters.deactivated != null)
          'deactivated': parameters.deactivated!,
        if (parameters.ttl != null) 'ttl': parameters.ttl!,
      },
      'state': state.toJson(),
    };
  }

  /// Extracts the version number from the versionId.
  ///
  /// The version number is a sequential integer that starts at 1 for the first
  /// log entry and increments by 1 for each subsequent entry. It allows tracking
  /// the chronological evolution of the DID Document.
  ///
  /// The versionId format is `"{versionNumber}-{entryHash}"`, and this getter
  /// extracts and parses the portion before the dash as an integer.
  ///
  /// Version numbering rules:
  /// - First entry must have version number 1
  /// - Each subsequent entry increments by exactly 1
  /// - No gaps or skips are allowed in the sequence
  ///
  /// Returns the version number as an integer.
  ///
  /// Example:
  /// ```dart
  /// final entry = DidWebVhLogEntry.fromJson({
  ///   'versionId': '5-z123abc456def',
  ///   ...
  /// });
  /// print(entry.versionNumber); // 5
  /// print(entry.versionId);     // "5-z123abc456def"
  /// ```
  ///
  /// See also:
  /// - [entryHash] - Extracts the cryptographic hash from versionId
  /// - [DidWebVhLog._verifyVersionNumberSequencing] - Validates sequential ordering
  int get versionNumber => int.parse(versionId.split('-').first);

  /// Extracts the entry hash from the versionId.
  ///
  /// The entry hash is the cryptographic hash (multihash-encoded, base58-btc) of
  /// the canonicalized log entry content. It provides integrity verification for
  /// the entry by allowing validators to recompute the hash and compare it.
  ///
  /// The versionId format is `"{versionNumber}-{entryHash}"`, and this getter
  /// returns the portion after the dash.
  ///
  /// Returns the entry hash as a multibase base58-btc encoded string (z-prefix).
  ///
  /// Example:
  /// ```dart
  /// final entry = DidWebVhLogEntry.fromJson({...});
  /// print(entry.versionId); // "1-z123abc456def"
  /// print(entry.entryHash);  // "z123abc456def"
  /// ```
  ///
  /// See also:
  /// - [versionNumber] - Extracts the numeric version from versionId
  /// - [DidWebVhLog._entryHashMustMatchWithHashOfEntryContent] - Validates this hash
  String get entryHash => versionId.split('-').last;
}

/// The DID Log file containing all versions of a DID.
///
/// The log is stored in JSON Lines format with one entry per line.
/// Each entry represents a version of the DID and must be processed
/// in order to resolve the current state.
class DidWebVhLog {
  /// Ordered list of log entries representing the complete version history.
  ///
  /// Entries must be processed sequentially from first to last to properly
  /// resolve the current DID state. Each entry builds upon the previous one
  /// with inherited parameter values unless explicitly overridden.
  final List<DidWebVhLogEntry> entries;

  DidWebVhLog({
    required this.entries,
  });

  /// Creates a [DidWebVhLog] from a JSON Lines formatted string.
  ///
  /// Parses a string containing newline-separated JSON objects (JSON Lines format)
  /// where each line represents a [DidWebVhLogEntry]. Empty lines and whitespace-only
  /// lines are automatically filtered out.
  ///
  /// The JSON Lines format is defined at https://jsonlines.org/
  ///
  /// Example:
  /// ```dart
  /// final jsonLines = '''
  /// {"versionId":"1-QmHash","versionTime":"2024-04-05T07:32:58Z",...}
  /// {"versionId":"2-QmHash","versionTime":"2024-04-05T08:00:00Z",...}
  /// ''';
  /// final log = DidWebVhLog.fromJsonLines(jsonLines);
  /// ```
  ///
  /// Throws [FormatException] if any line contains invalid JSON.
  /// Throws [TypeError] if required fields are missing in any entry.
  factory DidWebVhLog.fromJsonLines(String jsonLines) {
    final lines = jsonLines.split('\n');
    final entries = lines
        .where((line) => line.trim().isNotEmpty)
        .map((line) => DidWebVhLogEntry.fromJson(
            Map<String, dynamic>.from(jsonDecode(line))))
        .toList();
    return DidWebVhLog(entries: entries);
  }

  /// Verifies that the version number in an entry matches the expected sequence.
  ///
  /// Version numbers must start at 1 and increment by exactly 1 for each entry.
  ///
  /// Throws [SsiException] if the version number doesn't match the expected value.
  void _verifyVersionNumberSequencing(
      int actualVersionNum, int expectedVersionNum) {
    if (actualVersionNum != expectedVersionNum) {
      throw SsiException(
        message:
            'Invalid version number sequence. Expected $expectedVersionNum, got $actualVersionNum',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Verifies that timestamps are in strictly ascending order.
  ///
  /// For entries after the first, validates that the current entry's timestamp
  /// is strictly after the previous entry's timestamp.
  ///
  /// Throws [SsiException] if:
  /// - Timestamps are not in ascending order
  /// - Timestamp format is invalid (not ISO8601)
  void _verifyTimestampOrdering(DidWebVhLogEntry currentEntry,
      DidWebVhLogEntry? previousEntry, int versionNum) {
    if (previousEntry != null) {
      final prevTime = previousEntry.versionTime;
      final currTime = currentEntry.versionTime;
      if (!currTime.isAfter(prevTime)) {
        throw SsiDidResolutionException(
          message:
              'Version timestamps must be strictly ascending. Entry $versionNum has invalid timestamp',
          code: SsiExceptionType.invalidDidWebVh.code,
          resolutionMetadata: {
            'error': 'invalidDid',
            'message':
                'Version timestamps must be strictly ascending. Entry $versionNum has invalid timestamp',
          },
        );
      }
    }
  }

  /// Determines the index of the last entry to verify based on resolution metadata.
  ///
  /// Returns the index in the entries list up to which verification should be performed.
  /// If no metadata is provided, returns the last index (entries.length - 1).
  ///
  /// Throws [SsiException] if:
  /// - Multiple version parameters are provided
  /// - The specified version is not found in the log
  /// - No entries exist at or before the specified versionTime
  int _determineVerificationBoundary(DidResolutionOptions? resolutionOptions) {
    int verifyUpToIndex = entries.length - 1;

    if (resolutionOptions != null) {
      // Check that only one version parameter is provided
      final versionParams = ['versionId', 'versionNumber', 'versionTime'];
      final providedParams =
          versionParams.where((p) => resolutionOptions.containsKey(p)).toList();

      if (providedParams.length > 1) {
        throw SsiException(
          message:
              'Only one of versionId, versionNumber, or versionTime can be specified',
          code: SsiExceptionType.invalidDidWebVh.code,
        );
      }

      if (resolutionOptions.containsKey('versionId')) {
        final targetVersionId = resolutionOptions['versionId'] as String;
        final index = entries.indexWhere((e) => e.versionId == targetVersionId);
        if (index == -1) {
          throw SsiException(
            message: 'versionId $targetVersionId not found in log',
            code: SsiExceptionType.invalidDidWebVh.code,
          );
        }
        verifyUpToIndex = index;
      } else if (resolutionOptions.containsKey('versionNumber')) {
        final targetVersionNum = resolutionOptions['versionNumber'] as int;
        final index =
            entries.indexWhere((e) => e.versionNumber == targetVersionNum);
        if (index == -1) {
          throw SsiException(
            message: 'versionNumber $targetVersionNum not found in log',
            code: SsiExceptionType.invalidDidWebVh.code,
          );
        }
        verifyUpToIndex = index;
      } else if (resolutionOptions.containsKey('versionTime')) {
        final targetTime =
            DateTime.parse(resolutionOptions['versionTime'] as String);
        // Find last entry at or before targetTime
        verifyUpToIndex = -1;
        for (int i = 0; i < entries.length; i++) {
          final entryTime = entries[i].versionTime;
          if (entryTime.isAfter(targetTime)) {
            break;
          }
          verifyUpToIndex = i;
        }
        if (verifyUpToIndex == -1) {
          throw SsiException(
            message:
                'No entries found at or before versionTime ${resolutionOptions['versionTime']}',
            code: SsiExceptionType.invalidDidWebVh.code,
          );
        }
      }
    }

    return verifyUpToIndex;
  }

  /// Verifies that the method version is supported by this implementation.
  ///
  /// Currently, only "did:webvh:1.0" is supported. This is an implementation limitation
  /// to keep the code simple, not a specification requirement.
  ///
  /// Parameters:
  /// - [params]: The active parameters to validate
  ///
  /// Throws [SsiException] if the method version is not supported.
  void _parameterMethodMustBeVersion1(DidWebVhLogEntryParameters params) {
    if (params.method != 'did:webvh:1.0') {
      throw SsiException(
        message: 'Only did:webvh:1.0 method is supported',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Verifies that no updates occur after DID deactivation.
  ///
  /// Once a DID is deactivated (deactivated parameter set to true), no further
  /// log entries are permitted. This ensures the integrity of the deactivation state.
  ///
  /// Parameters:
  /// - [isDeactivated]: Whether the DID has been deactivated
  /// - [versionNum]: The current version number being validated
  ///
  /// Throws [SsiException] if the DID is already deactivated.
  void _mustBeNoUpdateAfterDeactivation(bool isDeactivated, int versionNum) {
    if (isDeactivated) {
      throw SsiException(
        message:
            'No updates allowed after deactivation. Found entry $versionNum after deactivation',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  ///
  /// Validates that the method parameter exists in the first log entry.
  ///
  /// The method parameter defines the did:webvh specification version (e.g., "did:webvh:1.0")
  /// and MUST be present in the first log entry. It determines which cryptographic algorithms
  /// and processing rules apply to the DID log.
  ///
  /// Parameters:
  /// - [params]: The active parameters after inheritance resolution
  ///
  /// Throws [SsiException] if the method parameter is null in the first entry.
  void _parameterMethodMustExistInFirstVersion(
      DidWebVhLogEntryParameters params) {
    if (params.method == null) {
      throw SsiException(
        message: 'First log entry must contain "method" parameter',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Validates that the SCID parameter exists in the first log entry.
  ///
  /// The SCID (Self-Certifying Identifier) is a hash of the DID's inception event
  /// and MUST be present in the first log entry. It MUST NOT appear in later entries.
  ///
  /// Parameters:
  /// - [params]: The active parameters after inheritance resolution
  ///
  /// Throws [SsiException] if the SCID parameter is null in the first entry.
  void _parameterScidMustExistInfirstVersion(
      DidWebVhLogEntryParameters params) {
    if (params.scid == null) {
      throw SsiException(
        message: 'First log entry must contain "scid" parameter',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Validates that the updateKeys parameter exists in the first log entry.
  ///
  /// The updateKeys array contains multikey-formatted public keys authorized to
  /// control the DID. It MUST be present in the first log entry.
  ///
  /// Parameters:
  /// - [params]: The active parameters after inheritance resolution
  ///
  /// Throws [SsiException] if the updateKeys parameter is null in the first entry.
  void _parameterUpdateKeysMustExistInFirstVersion(
      DidWebVhLogEntryParameters params) {
    if (params.updateKeys == null) {
      throw SsiException(
        message: 'First log entry must contain "updateKeys" parameter',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Validates that the SCID parameter does not appear in later log entries.
  ///
  /// The SCID (Self-Certifying Identifier) MUST only appear in the first log entry
  /// and MUST NOT appear in any subsequent entries.
  ///
  /// Parameters:
  /// - [params]: The entry parameters to validate
  ///
  /// Throws [SsiException] if the SCID parameter is present in a later entry.
  void _parameterScidCannotExistInLaterVersions(
      DidWebVhLogEntryParameters params) {
    if (params.scid != null) {
      throw SsiException(
        message: 'SCID parameter must only appear in first log entry',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Validates that the portable parameter cannot be changed from false to true.
  ///
  /// The portable parameter can ONLY be set to true in the first entry.
  /// Once set to false, it MUST NOT be changed to true in later entries.
  ///
  /// Parameters:
  /// - [prevActiveParameters]: The previous active parameters to validate against
  /// - [activeParameters]: The current active parameters
  ///
  /// Throws [SsiException] if portable is being changed from false to true.
  void _parameterPortableCannotBeTrueInLaterVersions(
      DidWebVhLogEntryParameters? prevActiveParameters,
      DidWebVhLogEntryParameters activeParameters) {
    if (prevActiveParameters?.portable == false &&
        activeParameters.portable == true) {
      throw SsiException(
        message:
            'Portable parameter can only be set to true in the first entry',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Verifies that the SCID matches the hash of the first log entry.
  ///
  /// The SCID (Self-Certifying Identifier) is calculated as the SHA-256 hash
  /// of the canonicalized (using JCS) first log entry with the proof field removed.
  /// This ensures the SCID is a cryptographic commitment to the inception event.
  ///
  /// According to the webvh spec:
  /// 1. Remove the 'proof' field from the first entry
  /// 2. Canonicalize the remaining entry using JCS (RFC 8785)
  /// 3. Hash the canonicalized string using SHA-256
  /// 4. Encode the hash as multibase base58-btc (z-prefix)
  /// 5. Compare with the SCID parameter value
  ///
  /// 1. Extract the first DID log entry and use it for the rest of the steps in this process.
  ///    1a. This method already takes the first entry as input, so this step is effectively done by the caller.
  /// 2. Extract the scid property value from the parameters in the DID log entry.
  /// 3. Determine the hash algorithm used by the DID Controller from the multihash scid value.
  /// 4. The hash algorithm MUST be one listed in the parameters defined by the version of the
  ///    did:webvh specification being used by the DID Controller based on the method parameters property.
  ///    3a. This implementation only supports did:webvh:1.0 which requires SHA-256.
  /// 5. Remove the data integrity proof property from the DID log entry.
  /// 6. Replace the versionId property value with the literal "{SCID}".
  /// 7. Treat the resulting log entry as a string and do a text replacement of the scid value from
  ///    Step 2 with the literal string {SCID}.
  /// 8. Use the result and the hash algorithm (from Step 3) as input to the function defined in
  ///    the Generate SCID section (above).
  ///    8a. Canonicalize the input string using JCS (RFC 8785).
  ///    8b. Hash the canonicalized string using the hash algorithm from Step 3.
  ///    8c. Encode the hash output as multibase base58-btc (z-prefix).
  /// 9. The output string MUST match the scid extracted in Step 2. If not, terminate the resolution
  ///    process with an error.
  ///
  /// Parameters:
  /// - [firstEntry]: The first log entry to verify
  ///
  /// Throws [SsiException] if the calculated SCID doesn't match the expected value.
  void _scidMustMatchWithHashOfFirstEntry(DidWebVhLogEntry firstEntry) {
    final String expectedScid = firstEntry.parameters.scid!;
    // Create a map representation of the first entry without the proof field
    final entryWithoutProof =
        firstEntry._buildMapFromEntryWithVersionIdAndStrippedProof('{SCID}');

    // Canonicalize using JCS and replace scid value with {SCID}
    final canonicalized = JcsUtil.canonicalize(entryWithoutProof)
        .replaceAll(expectedScid, '{SCID}');

    final retBytes = _multiHashSha256(canonicalized);

    // Encode as multibase base58-btc
    final calculatedScid = base58BitcoinEncode(retBytes);

    // Verify match
    if (calculatedScid != expectedScid) {
      throw SsiException(
        message:
            'SCID verification failed. Expected: $expectedScid, Calculated: $calculatedScid',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Encodes a SHA-256 hash in multihash format.
  ///
  /// Takes a message string, hashes it using SHA-256, and encodes the result
  /// in multihash format with the SHA-256 codec (0x12) and length prefix.
  ///
  /// Multihash format: [hash-function-code][digest-length][digest-bytes]
  ///
  /// Parameters:
  /// - [message]: The message string to hash
  ///
  /// Returns the multihash-encoded bytes.
  Uint8List _multiHashSha256(String message) {
    // Hash using SHA-256
    final hash = DigestUtils.getDigest(
      utf8.encode(message),
      hashingAlgorithm: HashingAlgorithm.sha256,
    );

    Uint8List encodeVarint(int value) {
      const _maxIntegerJS = 9007199254740991;
      // Ensure that the value is within JavaScript's safe integer range.
      if (value < 0 || value >= _maxIntegerJS) {
        throw ArgumentError.value(
          value,
          'value',
          'must be a non-negative integer less than $_maxIntegerJS',
        );
      }

      BytesBuilder writer = BytesBuilder();

      do {
        int temp = value & 0x7F; // 0x7F = 01111111

        value = value >> 7; // unsigned bit-right shift

        if (value != 0) {
          temp |= 0x80;
        }

        writer.addByte(temp.toInt());
      } while (value != 0);

      return writer.toBytes();
    }

    var b = BytesBuilder();
    b.add(encodeVarint(0x12)); // sha2-256 code
    b.add(encodeVarint(hash.length));
    b.add(hash);

    final retBytes = b.toBytes();
    return retBytes;
  }

  /// Verifies that the entryHash in versionId matches the hash of the log entry content.
  ///
  /// The entryHash is calculated as the SHA-256 hash of the canonicalized (using JCS)
  /// log entry with the proof field removed. The versionId format is "{versionNumber}-{entryHash}".
  ///
  /// According to the webvh spec:
  /// 1. Remove the 'proof' field from the entry
  /// 2. Canonicalize the remaining entry using JCS (RFC 8785)
  /// 3. Hash the canonicalized string using SHA-256
  /// 4. Encode the hash as multihash format
  /// 5. Encode as multibase base58-btc (z-prefix)
  /// 6. Compare with the entryHash portion of versionId
  ///
  /// Parameters:
  /// - [entry]: The log entry to verify
  ///
  /// Throws [SsiException] if the calculated entryHash doesn't match the versionId.
  void _entryHashMustMatchWithHashOfEntryContent(
      DidWebVhLogEntry entry, DidWebVhLogEntry? prevEntry) {
    final expectedEntryHash = entry.entryHash;

    // Create a map representation of the entry without the proof field
    final entryWithoutProof =
        entry._buildMapFromEntryWithVersionIdAndStrippedProof(
            prevEntry?.versionId ?? entry.parameters.scid!);

    // Canonicalize using JCS
    final canonicalized = JcsUtil.canonicalize(entryWithoutProof);

    final retBytes = _multiHashSha256(canonicalized);

    // Encode as multibase base58-btc
    final calculatedEntryHash = base58BitcoinEncode(retBytes);

    // Verify match
    if (calculatedEntryHash != expectedEntryHash) {
      throw SsiException(
        message:
            'EntryHash verification failed for version ${entry.versionNumber}. Expected: $expectedEntryHash, Calculated: $calculatedEntryHash',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }

  /// Verifies the integrity and validity of the DID log up to a specified version.
  ///
  /// This method validates the log entries according to the webvh specification,
  /// with optional verification boundaries specified through [resolutionMetadata].
  ///
  /// The [resolutionMetadata] parameter supports the following version specifiers:
  /// - `versionId`: Verifies up to and including the entry with this versionId (e.g., "3-QmHash123")
  /// - `versionNumber`: Verifies up to and including this version number (e.g., 5)
  /// - `versionTime`: Verifies up to the last entry at or before this timestamp (e.g., "2024-04-05T10:00:00Z")
  /// - Only ONE of these parameters should be provided
  /// - If none provided, verifies the entire log
  ///
  /// Performs comprehensive validation including:
  /// - Version number sequencing (must start at 1 and increment by 1)
  /// - Timestamp ordering (must be strictly ascending)
  /// - First entry requirements (must contain method, scid, and updateKeys)
  /// - Parameter inheritance rules (missing parameters inherit from previous entries)
  /// - Pre-rotation constraints (if active, nextKeyHashes and updateKeys must be present)
  /// - Portable flag constraints (can only be set to true in first entry)
  /// - Deactivation rules (no further updates after deactivation)
  /// - SCID calculation
  ///
  /// Note: This method performs structural and logical validation but does NOT verify:
  /// - Cryptographic signatures (Data Integrity proofs)
  /// - EntryHash values in versionId
  /// - Witness signatures
  /// - key pre-rotation
  ///
  ///
  /// Returns `true` if all validations pass.
  ///
  /// Throws [SsiException] with detailed error message if any validation fails.
  ///
  /// Example:
  /// ```dart
  /// final log = DidWebVhLog.fromJsonLines(jsonLines);
  ///
  /// // Verify entire log
  /// log.verify();
  ///
  /// // Verify up to version 5
  /// log.verify({'versionNumber': 5});
  ///
  /// // Verify up to specific versionId
  /// log.verify({'versionId': '3-QmHash123'});
  ///
  /// // Verify up to specific timestamp
  /// log.verify({'versionTime': '2024-04-05T10:00:00Z'});
  /// ```
  ///
  (DidDocument, DidDocumentMetadata?, DidResolutionMetadata?) verify(
      [DidResolutionOptions? resolutionOptions]) {
    if (entries.isEmpty) {
      throw SsiException(
        message: 'DID log is empty',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
    bool skipHashAndProofVerification =
        resolutionOptions?['skipHashAndProofVerification'] == true;
    // Determine verification boundary
    int verifyUpToIndex = _determineVerificationBoundary(resolutionOptions);

    // Track active parameters for inheritance
    DidWebVhLogEntryParameters activeParameters = DidWebVhLogEntryParameters();

    bool preRotationActive = false;
    bool isDeactivated = false;
    bool witnessActive = false;
    DidDocument? resolvedDidDoc = null;

    for (int i = 0; i <= verifyUpToIndex; i++) {
      final entry = entries[i];
      final isFirstEntry = i == 0;
      final prevEntry = isFirstEntry ? null : entries[i - 1];

      final versionNum = entry.versionNumber;

      _verifyVersionNumberSequencing(versionNum, i + 1);
      _verifyTimestampOrdering(entry, prevEntry, versionNum);

      final params = entry.parameters;
      final prevActiveParams = isFirstEntry ? null : activeParameters;

      // set active parameters
      activeParameters = DidWebVhLogEntryParameters(
        method: params.method ?? prevActiveParams?.method,
        scid: params.scid ?? prevActiveParams?.scid,
        updateKeys: params.updateKeys ?? prevActiveParams?.updateKeys,
        nextKeyHashes:
            params.nextKeyHashes ?? prevActiveParams?.nextKeyHashes ?? [],
        witness: params.witness ?? prevActiveParams?.witness ?? {},
        watchers: params.watchers ?? prevActiveParams?.watchers ?? [],
        portable: params.portable ?? prevActiveParams?.portable ?? false,
        deactivated:
            params.deactivated ?? prevActiveParams?.deactivated ?? false,
        ttl: params.ttl ?? prevActiveParams?.ttl ?? 3600,
      );
      // Apply validations applicable to all entries

      // Currently, only "did:webvh:1.0" is supported. This is an implementation limitation
      // to keep the code simple, not a specification requirement.
      // As per spec
      // Acceptable values:
      //     did:webvh:1.0
      //     Permitted hash algorithms: SHA-256 [RFC6234]
      //     Permitted Data Integrity cryptosuites: eddsa-jcs-2022 [DI-EDDSA-V1.0]
      _parameterMethodMustBeVersion1(activeParameters);
      _mustBeNoUpdateAfterDeactivation(isDeactivated, versionNum);

      // Apply first entry validations
      if (isFirstEntry) {
        _parameterMethodMustExistInFirstVersion(activeParameters);
        _parameterScidMustExistInfirstVersion(activeParameters);
        _parameterUpdateKeysMustExistInFirstVersion(activeParameters);
        _scidMustMatchWithHashOfFirstEntry(entry);
      }

      // Apply later entry validations
      if (!isFirstEntry) {
        _parameterScidCannotExistInLaterVersions(params);
        _parameterPortableCannotBeTrueInLaterVersions(
            prevActiveParams, activeParameters);

        // Pre-rotation constraints
        if (preRotationActive) {
          // TODO - Add validation for pre-rotation key constraints
        }

        if (witnessActive) {
          // TODO - Add validation that witness signatures are present and valid for this entry
        }
      }

      if (!skipHashAndProofVerification) {
        _entryHashMustMatchWithHashOfEntryContent(entry, prevEntry);
        // TODO - Add verification of data integrity proof signatures
      }

      // Update deactivation status
      if (activeParameters.deactivated == true) {
        isDeactivated = true;
      }
      // Update witness active status
      witnessActive = activeParameters.witness != null &&
          activeParameters.witness!.isNotEmpty;

      // Update prerotation active status
      preRotationActive = activeParameters.nextKeyHashes != null &&
          activeParameters.nextKeyHashes!.isNotEmpty;

      // Update resolved DID Document after processing this entry
      resolvedDidDoc = entry.state;
    }
    if (resolvedDidDoc == null) {
      throw SsiDidResolutionException(
        message:
            'Failed to resolve DID Document from log entries - no valid entries found according to query parameters',
        code: SsiExceptionType.invalidDidWebVh.code,
        resolutionMetadata: {
          'error': 'invalidDid',
          'message':
              'Failed to resolve DID Document from log entries - no valid entries found according to query parameters',
        },
      );
    }

    return (resolvedDidDoc, null, null);
  }
}

/// DidWebVh Class to handle Url parsing and components
class DidWebVh extends Did {
  DidWebVh._(String scheme, String method, String methodSpecificId)
      : super(
            scheme: scheme, method: method, methodSpecificId: methodSpecificId);

  /// Creates a [DidWebVh] instance from a DID string.
  ///
  /// Parses a DID string and validates that it conforms to the did:webvh specification.
  /// The DID must use the 'webvh' method and have a valid method-specific identifier
  /// that includes a SCID and an HTTPS URL location.
  ///
  /// The method-specific identifier format is: `{scid}:{domain}[:path...]`
  ///
  /// Example DID formats:
  /// - `did:webvh:z6Mk...ABC:example.com`
  /// - `did:webvh:z6Mk...ABC:example.com:path:to:resource`
  /// - `did:webvh:z6Mk...ABC:example.com?versionId=1-hash`
  ///
  /// Parameters:
  /// - [didString]: A string representation of a did:webvh DID
  ///
  /// Returns a [DidWebVh] instance with parsed components.
  ///
  /// Throws [FormatException] if the DID string is not a valid URI format.
  ///
  /// Throws [SsiException] if:
  /// - The DID method is not 'webvh'
  /// - The method-specific identifier cannot be parsed
  /// - The HTTPS URL or SCID extraction fails
  ///
  /// Example:
  /// ```dart
  /// final did = DidWebVh.parse('did:webvh:z6Mk...ABC:example.com');
  /// print(did.scid); // 'z6Mk...ABC'
  /// print(did.httpsUrl); // 'https://example.com'
  /// ```
  ///
  factory DidWebVh.parse(String didString) {
    final did = Did.parse(didString);
    if (did.method != 'webvh') {
      throw SsiException(
          message: 'Unsupported DID method. Expected method: webvh',
          code: SsiExceptionType.invalidDidWebVh.code);
    }

    final String methodSpecificId = did.methodSpecificId;
    getScidFromMethodSpecificId(methodSpecificId);
    getHttpsUrlFromMethodSpecificId(methodSpecificId);

    return DidWebVh._(did.scheme, did.method, did.methodSpecificId);
  }

  /// The Self-Certifying Identifier (SCID) component of the DID WebVH.
  ///
  /// The SCID is the first component of the method-specific identifier and is a
  /// cryptographic hash of the DID's inception event. It provides a self-certifying
  /// identifier that ensures the DID's integrity.
  ///
  /// Example:
  /// ```dart
  /// final did = DidWebVh.fromDidString('did:webvh:z6Mk...ABC:example.com');
  /// print(did.scid); // 'z6Mk...ABC'
  /// ```
  String get scid {
    return getScidFromMethodSpecificId(super.methodSpecificId);
  }

  @override
  Future<(DidDocument, DidDocumentMetadata?, DidResolutionMetadata?)>
      resolveDid([DidResolutionOptions? options]) async {
    final nnOptions = options ?? {};
    final http.Response response = await downloadJsonLogFile();
    final didWebVhLog1 = DidWebVhLog.fromJsonLines(response.body);
    httpsUrl.queryParameters.entries.forEach((entry) {
      if (!nnOptions.keys.contains(entry.key)) {
        nnOptions[entry.key] = entry.value;
      }
    });
    final (doc, dm, rm) = didWebVhLog1.verify(nnOptions);
    return (doc, dm, rm);
  }

  /// The HTTPS URL derived from the DID WebVH method-specific identifier.
  ///
  /// Converts the DID's method-specific identifier (excluding the SCID) into an HTTPS URL
  /// where the DID document log file is hosted. This URL is used to retrieve the DID log.
  ///
  /// The conversion follows these rules:
  /// - Colons (:) are converted to slashes (/)
  /// - %3A is decoded to colon (:)
  /// - %2B is decoded to slash (/)
  /// - Query parameters and fragments are preserved
  ///
  /// Example:
  /// ```dart
  /// final did = DidWebVh.fromDidString('did:webvh:z6Mk...ABC:example.com:path');
  /// print(did.httpsUrl); // https://example.com/path
  /// ```
  Uri get httpsUrl {
    return getHttpsUrlFromMethodSpecificId(super.methodSpecificId);
  }

  /// Extracts and converts the HTTPS URL from a DID WebVH method-specific identifier.
  ///
  /// This static method parses the method-specific identifier, removes the SCID component,
  /// and converts the remaining parts into an HTTPS URL according to the WebVH specification.
  ///
  /// The conversion process:
  /// 1. Splits the method-specific identifier by colons
  /// 2. Removes the first part (SCID)
  /// 3. Converts remaining parts to URL format
  /// 4. Applies decoding rules (%3A → :, %2B → /)
  /// 5. Validates query parameters
  ///
  /// Parameters:
  /// - [methodSpecificId]: The method-specific identifier from a did:webvh DID
  ///
  /// Returns the HTTPS URI where the DID log is hosted.
  ///
  /// Throws [SsiException] if multiple version query parameters are provided.
  ///
  /// Example:
  /// ```dart
  /// final url = DidWebVh.getHttpsUrlFromMethodSpecificId('z6Mk...ABC:example.com:path');
  /// print(url); // https://example.com/path
  /// ```
  static Uri getHttpsUrlFromMethodSpecificId(String methodSpecificId) {
    final [scid, ...urlParts] = methodSpecificId.split(':');
    String urlString = urlParts.join(':');

    String? fragment;
    if (urlString.contains('#')) {
      [urlString, fragment] = urlString.split('#');
    }

    String? query;
    if (urlString.contains('?')) {
      [urlString, query] = urlString.split('?');
    }

    urlString = urlString.replaceAll(':', '/');
    urlString = urlString.replaceAll('%3A', ':');
    urlString = urlString.replaceAll('%2B', '/');
    urlString = 'https://$urlString';

    query != null //
        ? urlString = '$urlString?$query'
        : urlString = urlString;
    fragment != null
        ? urlString = '$urlString#$fragment'
        : urlString = urlString;

    final didUrl = Uri.parse(urlString);

    /// Only one of versionId, versionTime, or versionNumber is allowed in the query parameters
    final versionQueryParamCount = didUrl.queryParameters.entries
        .where((entry) =>
            ['versionId', 'versionTime', 'versionNumber'].contains(entry.key))
        .length;

    if (versionQueryParamCount > 1) {
      throw SsiException(
          message:
              'Only one of versionId, versionTime, or versionNumber is allowed in the query parameters',
          code: SsiExceptionType.invalidDidWebVh.code);
    }

    return didUrl;
  }

  /// Extracts the SCID (Self-Certifying Identifier) from a method-specific identifier.
  ///
  /// The SCID is always the first component of the method-specific identifier,
  /// before the first colon. It is a cryptographic hash that certifies the
  /// authenticity of the DID's inception event.
  ///
  /// Parameters:
  /// - [methodSpecificId]: The method-specific identifier from a did:webvh DID
  ///
  /// Returns the SCID component as a string.
  ///
  /// Example:
  /// ```dart
  /// final scid = DidWebVh.getScidFromMethodSpecificId('z6Mk...ABC:example.com:path');
  /// print(scid); // 'z6Mk...ABC'
  /// ```
  static String getScidFromMethodSpecificId(String methodSpecificId) {
    final [scid, ..._] = methodSpecificId.split(':');
    return scid;
  }

  /// The full HTTPS URL to the DID WebVH JSON log file.
  ///
  /// Constructs the complete URL where the DID log file (did.jsonl) is hosted.
  /// If the HTTPS URL has an empty path, `/.well-known` is inserted before `/did.jsonl`
  /// according to the WebVH specification.
  ///
  /// URL construction rules:
  /// - If path is empty: `https://example.com/.well-known/did.jsonl`
  /// - If path exists: `https://example.com/path/did.jsonl`
  ///
  /// Returns a string representation of the URL.
  ///
  /// Example:
  /// ```dart
  /// final did = DidWebVh.fromDidString('did:webvh:z6Mk...ABC:example.com');
  /// print(did.jsonLogFileHttpsUrlString); // 'https://example.com/.well-known/did.jsonl'
  /// ```
  String get jsonLogFileHttpsUrlString {
    return '${httpsUrl.toString()}${httpsUrl.hasEmptyPath ? '/.well-known' : ''}/did.jsonl';
  }

  /// Downloads the JSON log file from the URL represented by this DidWebVhUrl
  Future<http.Response> downloadJsonLogFile([http.Client? client]) async {
    client ??= http.Client();
    try {
      var res = await client
          .get(Uri.parse(jsonLogFileHttpsUrlString))
          .timeout(const Duration(seconds: 30), onTimeout: () {
        return http.Response('Timeout', 408);
      });

      if (res.statusCode == 200) {
        return res;
      } else {
        throw SsiException(
          message: 'Failed to fetch DIDWebVH JSON Log file for ${toString()}',
          code: SsiExceptionType.invalidDidWebVh.code,
          originalMessage:
              'HTTP status code: ${res.statusCode} for URL: ${jsonLogFileHttpsUrlString}',
        );
      }
    } catch (e) {
      // Re-throw if already an SsiException
      if (e is SsiException) rethrow;

      // Handle any HTTP errors (connection refused, timeouts, etc.)
      throw SsiException(
        message: 'Failed to fetch DIDWebVH JSON Log file for ${toString()}: $e',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }
}
