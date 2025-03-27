import 'dart:convert';

import 'package:sdjwt_sdk/src/models/disclosure.dart';
import 'package:sdjwt_sdk/src/models/disclosure_map.dart';
import 'package:sdjwt_sdk/src/models/disclosure_path.dart';

import '../base/hasher.dart';

/// Output class for the disclosure unpacking process.
///
/// Contains the unpacked payload with all disclosures applied and a map of
/// disclosures indexed by their paths in the JSON structure.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class UnpackedDisclosuresOutput {
  /// The unpacked payload with all disclosures applied.
  final Map<String, dynamic> unpackedPayload;

  /// A map of disclosures indexed by their paths in the JSON structure.
  final Map<String, Disclosure> disclosuresPathIndex;

  /// Creates a new output for the disclosure unpacking process.
  ///
  /// Parameters:
  /// - **[unpackedPayload]**: The unpacked payload with all disclosures applied.
  /// - **[disclosuresPathIndex]**: A map of disclosures indexed by their paths in the JSON structure.
  UnpackedDisclosuresOutput(
      {required this.unpackedPayload, required this.disclosuresPathIndex});
}

/// Unpacks disclosures in an SD-JWT payload.
///
/// This function resolves all selective disclosure references in the payload
/// by replacing them with their actual values from the disclosure map.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// Parameters:
/// - **[tokenPayload]**: The original SD-JWT payload.
/// - **[disclosuresDigestIndex]**: A map of disclosures indexed by their digest values.
/// - **[hasher]**: The [Hasher] used for the disclosures.
///
/// Returns an [UnpackedDisclosuresOutput] containing the unpacked payload and a map
/// of disclosures indexed by their paths.
UnpackedDisclosuresOutput unpackDisclosures({
  required Map<String, dynamic> tokenPayload,
  required DisclosureMap disclosuresDigestIndex,
  required Hasher<String, String> hasher,
}) {
  final Map<String, dynamic> resolvedPayload =
      jsonDecode(jsonEncode(tokenPayload));
  resolvedPayload.remove('_sd_alg');

  final Map<String, Disclosure> disclosurePaths = {};
  final pointer = DisclosurePath.root();
  _unpackMap(resolvedPayload, disclosuresDigestIndex, disclosurePaths, pointer);
  return UnpackedDisclosuresOutput(
    unpackedPayload: resolvedPayload,
    disclosuresPathIndex: disclosurePaths,
  );
}

// Process _sd claims recursively
void _unpackMap(Map<String, dynamic> payload, DisclosureMap disclosureHashMap,
    Map<String, Disclosure> disclosurePaths, DisclosurePath pointer) {
  final List<String> keysToProcess = payload.keys.toList();

  for (final key in keysToProcess) {
    final value = payload[key];

    if (key == '_sd') {
      if (value is! List<dynamic>) {
        throw Exception(
            "Invalid SD-JWT: _sd should be a list of hash strings. But got $value");
      }

      // Handle array of disclosure hashes
      for (final hash in value) {
        if (hash is! String) {
          throw Exception(
              "Invalid SD-JWT: _sd should be a list of hash strings. But got $hash");
        }

        final Disclosure? disclosure = disclosureHashMap[hash];

        // if disclosure is null, then it is a decoy or undisclosed detail. Ignore it.
        if (disclosure != null) {
          final newKey = disclosure.claimName!;
          final value = jsonDecode(jsonEncode(disclosure.claimValue));

          payload[newKey] = value;

          final newPointer = pointer.segment(newKey);
          disclosurePaths[newPointer.toString()] = disclosure;
          disclosure.pointer = newPointer;

          _unpackValue(value, disclosureHashMap, disclosurePaths, newPointer);
        }
      }

      // Remove SD-JWT specific claims after processing
      payload.remove('_sd');
    } else {
      final newPointer = pointer.segment(key);
      _unpackValue(value, disclosureHashMap, disclosurePaths, newPointer);
    }
  }
}

void _unpackList(List<dynamic> payload, DisclosureMap disclosureHashMap,
    Map<String, Disclosure> disclosurePaths, DisclosurePath pointer) {
  final payloadCopy = [...payload];
  final indicesForRemoval = <int>[];
  for (final (index, item) in payloadCopy.indexed) {
    final newPointer = pointer.segment(index.toString());

    if (item is Map<String, dynamic> && item['...'] != null) {
      final disclosure = disclosureHashMap[item['...']];

      if (disclosure != null) {
        final value = jsonDecode(jsonEncode(disclosure.claimValue));

        payload[index] = value;

        disclosurePaths[newPointer.toString()] = disclosure;
        disclosure.pointer = newPointer;

        _unpackValue(
            payload[index], disclosureHashMap, disclosurePaths, newPointer);
      } else {
        // it's either a decoy or an undisclosed value. Remove it.
        indicesForRemoval.add(index);
      }
    } else {
      _unpackValue(item, disclosureHashMap, disclosurePaths, newPointer);
    }
    indicesForRemoval.sort(
        (a, b) => b.compareTo(a)); // can cause idx out otherwise of bounds!
    // cleanup payload
    for (final index in indicesForRemoval) {
      if (index >= 0 && index < payload.length) {
        payload.removeAt(index);
      }
    }
  }
}

void _unpackValue(dynamic payload, DisclosureMap disclosureHashMap,
    Map<String, Disclosure> disclosurePaths, DisclosurePath pointer) {
  if (payload is Map<String, dynamic>) {
    _unpackMap(payload, disclosureHashMap, disclosurePaths, pointer);
  } else if (payload is List<dynamic>) {
    _unpackList(payload, disclosureHashMap, disclosurePaths, pointer);
  }
}
