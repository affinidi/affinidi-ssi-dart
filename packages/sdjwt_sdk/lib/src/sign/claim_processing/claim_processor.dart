import 'package:sdjwt_sdk/src/sign/claim_processing/sd_key_processor.dart';

import '../../../sdjwt_sdk.dart';
import '../../base/action.dart';
import '../../utils/stack.dart';
import 'claim_processing_visitor.dart';

/// Input data for the claim processor.
///
/// Contains all the necessary information to process claims according to the SD-JWT specification.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class ClaimProcessorInput {
  /// The claims to be processed for selective disclosure.
  final Map<String, dynamic> sdClaims;

  /// The disclosure frame specifying which claims should be selectively disclosable.
  final Map<String, dynamic> disclosureFrame;

  /// The set of disclosures to be generated during processing.
  final Set<Disclosure> disclosures;

  /// The [Hasher] used for creating disclosure digests.
  final Hasher<String, String> hasher;

  /// Creates a new claim processor input.
  ///
  /// Parameters:
  /// - **[sdClaims]**: The claims to be processed.
  /// - **[disclosureFrame]**: The disclosure frame specifying which claims should be selectively disclosable.
  /// - **[disclosures]**: The set of disclosures to be generated.
  /// - **[hasher]**: The [Hasher] for creating disclosure digests.
  ClaimProcessorInput(
      this.sdClaims, this.disclosureFrame, this.disclosures, this.hasher);
}

/// Processes claims according to the SD-JWT specification.
///
/// This class is responsible for traversing the claim structure and applying
/// selective disclosure transformations based on the provided disclosure frame.
/// It uses a visitor pattern to process each claim element and generate the
/// necessary disclosures.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// ### Specification Reference:
/// This implementation is inspired by the [Selective Disclosure for JWTs (SD-JWT)](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html)
/// specification. While it aims to align with the spec, certain implementation
/// details may vary based on project-specific requirements.
///
/// ### Key Responsibilities:
/// - Goes across the claim structure using a stack-based approach.
/// - Apply selective disclosure transformations using the provided disclosure frame.
/// - Generate disclosures and process their digests using the specified hasher.
///
/// ### Usage:
/// Represent the `ClaimProcessor` and call the `execute` method with a
/// `ClaimProcessorInput` object containing the claims, disclosure frame, disclosures,
/// and hasher.
///
/// Example:
/// ```dart
/// final processor = ClaimProcessor();
/// processor.execute(ClaimProcessorInput(
///   sdClaims: claims,
///   disclosureFrame: frame,
///   disclosures: disclosuresSet,
///   hasher: Base64EncodedOutputHasher.base64Sha256,
/// ));
/// ```
class ClaimProcessor extends Action<ClaimProcessorInput, void> {
  /// The processor for handling SD keys.
  final _sdKeyProcessor = SdKeyProcessor();

  @override
  void execute(ClaimProcessorInput input) {
    final visitor = ClaimProcessingVisitor(
        input.disclosures, input.hasher, _sdKeyProcessor);
    final rootElement = MapClaimElement(
      input.sdClaims,
      input.disclosureFrame,
      <String>[],
    );

    final stack = Stack<ClaimElement>(source: [rootElement]);
    while (stack.isNotEmpty) {
      final element = stack.pop();
      element.accept(visitor, '');
      stack.pushAll(visitor.stack);
      visitor.stack.clear();
    }
  }
}
