import '../../../sdjwt_sdk.dart';
import '../../base/action.dart';
import '../../utils/common.dart';
import '../decoy_digest_generator.dart';

/// Input data for the SD key processor.
///
/// Contains all the necessary information to process SD keys according to the SD-JWT specification.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class SdKeyProcessorInput {
  /// The current object being processed.
  final dynamic currentObject;

  /// The frame value specifying which elements should be selectively disclosable.
  final List<dynamic> frameValue;

  /// List of SD hashes that are local to the current object.
  final List<String> localSdHashes;

  /// The set of disclosures to be generated during processing.
  final Set<Disclosure> disclosures;

  /// The [Hasher] used for creating disclosure digests.
  final Hasher<String, String> hasher;

  /// The path prefix to use when processing this object.
  final String pathPrefix;

  /// The number of decoy digests to add for privacy protection.
  final int decoyCount;

  /// Creates a new SD key processor input.
  ///
  /// Parameters:
  /// - **[currentObject]**: The current object being processed.
  /// - **[frameValue]**: The frame value specifying which elements should be selectively disclosable.
  /// - **[localSdHashes]**: List of SD hashes that are local to the current object.
  /// - **[disclosures]**: The set of disclosures to be generated.
  /// - **[hasher]**: The [Hasher] for creating disclosure digests.
  /// - **[pathPrefix]**: The path prefix to use when processing this object.
  /// - **[decoyCount]**: The number of decoy digests to add (defaults to 0).
  SdKeyProcessorInput(this.currentObject, this.frameValue, this.localSdHashes,
      this.disclosures, this.hasher, this.pathPrefix,
      {this.decoyCount = 0});
}

/// Processes SD keys according to the SD-JWT specification.
///
/// This class is responsible for handling the selective disclosure transformations
/// for both object and array structures.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class SdKeyProcessor extends Action<SdKeyProcessorInput, void> {
  @override
  void execute(SdKeyProcessorInput input) {
    if (input.currentObject is List) {
      _processArrayDisclosures(input);
    } else if (input.currentObject is Map<String, Object?>) {
      _processObjectDisclosures(input);
    } else {
      throw ArgumentError('Unsupported structure for ${input.pathPrefix}');
    }
  }

  void _processArrayDisclosures(SdKeyProcessorInput input) {
    for (final discloseIndex in input.frameValue) {
      if (discloseIndex is! int ||
          discloseIndex < 0 ||
          discloseIndex >= (input.currentObject as List).length) {
        throw ArgumentError(
            'Index $discloseIndex is out of bounds at ${input.pathPrefix}');
      }

      final value = input.currentObject[discloseIndex];
      if (value == null) {
        throw ArgumentError(
            'Value at index $discloseIndex is null in ${input.pathPrefix}');
      }

      final disclosure = Disclosure.from(
        salt: generateSecureSalt(),
        claimValue: value,
        hasher: input.hasher,
      );
      _processDisclosure(disclosure, input.disclosures, input.localSdHashes);
      input.currentObject[discloseIndex] = {"...": input.localSdHashes.last};
    }
    if (input.decoyCount > 0) {
      final decoys = createDecoys(input.decoyCount, input.hasher);
      for (final decoy in decoys) {
        input.currentObject.add({"...": decoy});
      }
    }
  }

  void _processObjectDisclosures(SdKeyProcessorInput input) {
    final currentObject = input.currentObject as Map<String, Object?>;
    for (final discloseKey in input.frameValue) {
      final fieldValue = currentObject[discloseKey];
      if (fieldValue == null) {
        throw ArgumentError(
            'Disclosure key $discloseKey not found or is null at ${input.pathPrefix}');
      }

      final disclosure = Disclosure.from(
        salt: generateSecureSalt(),
        claimName: discloseKey,
        claimValue: fieldValue,
        hasher: input.hasher,
      );
      _processDisclosure(disclosure, input.disclosures, input.localSdHashes);
      currentObject.remove(discloseKey);
    }
    if (input.decoyCount > 0) {
      final decoys = createDecoys(input.decoyCount, input.hasher);
      input.localSdHashes.addAll(decoys);
    }
  }

  void _processDisclosure(
    Disclosure disclosure,
    Set<Disclosure> disclosures,
    List<String> localSdHashes,
  ) {
    disclosures.add(disclosure);
    final hashBase64 = disclosure.digest;
    localSdHashes.add(hashBase64);
  }
}

/// Creates a set of decoy digests for privacy protection.
///
/// Decoy digests are used to improve privacy by adding fake,
/// random digests along with real ones.
/// This makes it harder to tell how many real disclosures are in the data.
///
/// ### Parameters:
/// - **[count]**: The number of decoy digests to generate.
/// - **[hasher]**: The [Hasher] to use for generating the digests.
///
/// ### Returns:
/// A set of decoy digest strings.
///
/// ### Example:
/// ```dart
/// final decoys = createDecoys(3, Base64EncodedOutputHasher.base64Sha256);
/// print(decoys);
/// // Output: {'randomDigest1', 'randomDigest2', 'randomDigest3'}
/// ```
Set<String> createDecoys(int count, Hasher<String, String> hasher) {
  final decoyGenerator = DecoyDigestGenerator(hasher);
  return decoyGenerator.execute(count);
}
