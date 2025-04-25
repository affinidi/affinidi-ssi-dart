import '../../../did/did_signer.dart';
import '../models/parsed_vp.dart';
import '../models/verifiable_presentation.dart';

/// Defines operations for working with Verifiable Presentations.
abstract class VerifiablePresentationSuite<
    SerializedType,
    VP extends VerifiablePresentation,
    ParsedVP extends ParsedVerifiablePresentation<SerializedType>,
    Options> {
  /// Determines whether the provided [data] can be parsed by this suite.
  bool canParse(Object data);

  /// Parses the [data] into a verifiable presentation.
  ///
  /// Throws an exception if the [data] cannot be converted to a valid
  /// [ParsedVerifiablePresentation].
  ///
  /// Note: Implementers must check if the input can be parsed by this
  /// suite before attempting to parse.
  ParsedVP parse(Object data);

  /// Verifies the cryptographic integrity of the [input] presentation.
  Future<bool> verifyIntegrity(ParsedVP input);
}
