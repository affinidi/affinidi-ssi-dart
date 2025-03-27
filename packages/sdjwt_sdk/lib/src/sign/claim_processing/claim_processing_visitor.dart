import '../../../sdjwt_sdk.dart';
import '../../utils/stack.dart';
import 'sd_key_processor.dart';

/// A base abstract class representing an element in a claim structure.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// Parameters:
/// - **[T]**: The type of value this claim field holds. Possible types include:
///   - `Map<String, Object?>` for map structures.
///   - `List<dynamic>` for list structures.
///   - Any other type representing a specific claim value.
///
/// ### Additional Notes:
/// - **SD Hashes**: These are cryptographic hashes used to represent selectively disclosable (SD) data.
///   For example, an SD hash might look like `sha256:abc123...` and is used to verify the integrity of disclosed data.
/// - **Local SD Hashes**: These are SD hashes specific to the current claim element, stored in the `localSdHashes` list.
///   They are used to track which parts of the claim element are selectively disclosable.
abstract class ClaimElement<T> {
  /// The disclosure frame that specifies which parts of this element should be selectively disclosable.
  final dynamic disclosureFrame;

  /// List of SD hashes that are local to this claim element.
  ///
  /// Example:
  /// ```dart
  /// localSdHashes = ['sha256:abc123...', 'sha256:def456...'];
  /// ```
  final List<String> localSdHashes;

  /// The actual value of this claim element.
  ///
  /// Example:
  /// - For a map structure: `{'key1': 'value1', 'key2': 'value2'}`
  /// - For a list structure: `['item1', 'item2', 'item3']`
  final T value;

  /// Creates a new claim element with the specified disclosure frame, local SD hashes, and value.
  ///
  /// This constructor is used to initialize a claim element, which represents a part of a claim structure
  /// in the SD-JWT (Selective Disclosure JSON Web Token) framework. The claim element can hold various types
  /// of data (e.g., maps, lists, or specific values) and is designed to support selectively disclosable data.
  ///
  /// Parameters:
  /// - **[disclosureFrame]**: The disclosure frame for this element, specifying which parts of the element
  ///   should be selectively disclosable.
  /// - **[localSdHashes]**: A list of cryptographic hashes (SD hashes) that are local to this element,
  ///   used to track selectively disclosable data.
  /// - **[value]**: The actual value of this element, which can be a map, list, or any other type of data.
  ClaimElement(this.disclosureFrame, this.localSdHashes, this.value);

  /// Accepts a visitor to process this claim element.
  ///
  /// Parameters:
  /// - **[visitor]**: The visitor that will process this element.
  /// - **[pathPrefix]**: The path prefix to use when processing this element.
  void accept(ClaimVisitor visitor, String pathPrefix);
}

/// A claim element that represents a map structure.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class MapClaimElement extends ClaimElement<Map<String, Object?>> {
  /// Creates a new map claim element with the specified value, disclosure frame, and local SD hashes.
  ///
  /// Parameters:
  /// - **[value]**: The map value of this element.
  /// - **[disclosureFrame]**: The disclosure frame for this element.
  /// - **[localSdHashes]**: List of SD hashes local to this element.
  MapClaimElement(Map<String, Object?> value, dynamic disclosureFrame,
      List<String> localSdHashes)
      : super(disclosureFrame, localSdHashes, value);

  @override
  void accept(ClaimVisitor visitor, String pathPrefix) {
    visitor.visitMap(this, pathPrefix);
  }
}

/// A claim element that represents a list structure.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class ListClaimElement extends ClaimElement<List<dynamic>> {
  /// Creates a new list claim element with the specified value, disclosure frame, and local SD hashes.
  ///
  /// Parameters:
  /// - **[value]**: The list value of this element.
  /// - **[disclosureFrame]**: The disclosure frame for this element.
  /// - **[localSdHashes]**: List of SD hashes local to this element.
  ListClaimElement(
      List<dynamic> value, dynamic disclosureFrame, List<String> localSdHashes)
      : super(disclosureFrame, localSdHashes, value);

  @override
  void accept(ClaimVisitor visitor, String pathPrefix) {
    visitor.visitList(this, pathPrefix);
  }
}

/// A visitor interface for processing claim elements.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// This interface defines methods for visiting different types of claim elements
/// (e.g., map and list structures) in the SD-JWT (Selective Disclosure JSON Web Token) framework.
/// The visitor pattern allows for implementing custom logic to process claim elements
/// without modifying their structure.
///
/// ### Purpose:
/// - To efficiently process and analyze claim elements in an organized way.
/// - To apply specific logic, such as validating disclosure frames, generating disclosures,
///   or updating selectively disclosable data.
///
/// Example Use Case:
/// - A `ClaimProcessingVisitor` implementation might validate the structure of claims,
///   process selectively disclosable keys (`_sd`), and update local SD hashes.
abstract class ClaimVisitor {
  /// Visits a map claim element.
  ///
  /// Parameters:
  /// - **[element]**: The map claim element to visit.
  /// - **[pathPrefix]**: The path prefix to use when processing this element.
  void visitMap(MapClaimElement element, String pathPrefix);

  /// Visits a list claim element.
  ///
  /// Parameters:
  /// - **[element]**: The list claim element to visit.
  /// - **[pathPrefix]**: The path prefix to use when processing this element.
  void visitList(ListClaimElement element, String pathPrefix);
}

/// A visitor implementation that processes claims according to the SD-JWT specification.
class ClaimProcessingVisitor implements ClaimVisitor {
  /// The set of disclosures to be generated during processing.
  final Set<Disclosure> disclosures;

  /// The [Hasher] used for creating disclosure digests.
  final Hasher<String, String> hasher;

  /// The processor for handling SD keys.
  final SdKeyProcessor sdKeyProcessor;

  /// A stack of claim elements to be processed.
  final Stack<ClaimElement> stack = Stack(source: []);

  /// Creates a new claim processing visitor.
  ///
  /// Parameters:
  /// - **[disclosures]**: The set of disclosures to be generated.
  /// - **[hasher]**: The [Hasher] for creating disclosure digests.
  /// - **[sdKeyProcessor]**: The processor for handling SD keys.
  ClaimProcessingVisitor(this.disclosures, this.hasher, this.sdKeyProcessor);

  @override
  void visitMap(MapClaimElement element, String pathPrefix) {
    _validateDisclosureFrame(element.disclosureFrame, pathPrefix);

    for (final key in element.disclosureFrame.keys) {
      final fullPath = constructFullPath(pathPrefix, key);
      final frameValue = element.disclosureFrame[key];

      if (key == '_sd') {
        _processSdKey(element, frameValue, fullPath);
      } else {
        _processNestedStructure(element.value[key], frameValue, fullPath);
      }
    }

    _updateLocalHashes(element);
  }

  @override
  void visitList(ListClaimElement element, String pathPrefix) {
    _validateDisclosureFrame(element.disclosureFrame, pathPrefix);

    for (final key in element.disclosureFrame.keys) {
      final fullPath = constructFullPath(pathPrefix, key);
      final frameValue = element.disclosureFrame[key];

      if (key == '_sd') {
        _processSdKey(element, frameValue, fullPath);
      } else if (key != '_sd_decoy') {
        final index = int.tryParse(key);
        if (index != null && index >= 0 && index < element.value.length) {
          _processNestedStructure(element.value[index], frameValue, fullPath);
        } else {
          throw ArgumentError('Invalid array index $key at $fullPath');
        }
      }
    }
  }

  void _validateDisclosureFrame(dynamic frame, String pathPrefix) {
    if (frame is! Map<String, Object?>) {
      throw ArgumentError('Invalid disclosure frame structure at $pathPrefix');
    }
  }

  void _processSdKey(
    ClaimElement element,
    dynamic frameValue,
    String fullPath,
  ) {
    if (frameValue is List) {
      final decoyCount = element.disclosureFrame.containsKey('_sd_decoy')
          ? element.disclosureFrame['_sd_decoy']
          : 0;

      final currentObject = element.value;
      final localHashes = element.localSdHashes;

      sdKeyProcessor.execute(SdKeyProcessorInput(
          currentObject, frameValue, localHashes, disclosures, hasher, fullPath,
          decoyCount: decoyCount));
    } else {
      throw ArgumentError('Invalid _sd structure at $fullPath');
    }
  }

  void _processNestedStructure(
    dynamic currentValue,
    dynamic frameValue,
    String fullPath,
  ) {
    if (currentValue is Map<String, Object?>) {
      stack.push(MapClaimElement(
        currentValue,
        frameValue,
        <String>[],
      ));
    } else if (currentValue is List<dynamic>) {
      stack.push(ListClaimElement(
        currentValue,
        frameValue,
        <String>[],
      ));
    }
  }

  void _updateLocalHashes(ClaimElement element) {
    if (element is MapClaimElement && element.localSdHashes.isNotEmpty) {
      element.value["_sd"] = element.localSdHashes;
    }
  }
}

/// Constructs a full path by combining a path prefix and a key.
///
/// Parameters:
/// - **[pathPrefix]**: The prefix of the path.
/// - **[key]**: The key to append to the path.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// Returns a string representing the full path.
String constructFullPath(String pathPrefix, String key) {
  return pathPrefix.isEmpty ? key : '$pathPrefix.[$key]';
}
