import '../../../ssi.dart';
import '../models/parsed_vc.dart';

/// Class that contains operations to be done on encoded VCs
abstract class VerifiableCredentialSuite<SerializedType, Options> {
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  bool canParse(Object data);

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  ///
  /// Note: Implementers must check if the input can be parsed by the
  /// implementing suite
  ParsedVerifiableCredential<SerializedType> parse(Object data);

  /// Verify the integrity of [input]
  Future<bool> verifyIntegrity(SerializedType input);

  /// Prepare an Encoded VC based on the
  Future<SerializedType> issue(
    VerifiableCredential vc,
    DidSigner signer, {
    Options? options,
  });
}
