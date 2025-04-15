import '../../did/did_signer.dart';
import '../models/parsed_vc.dart';
import '../models/verifiable_credential.dart';

/// Defines operations for working with encoded Verifiable Credentials.
abstract interface class VerifiableCredentialSuite<
    SerializedType,
    VC extends VerifiableCredential,
    ParsedVC extends ParsedVerifiableCredential<SerializedType>,
    Options> {
  /// Determines whether the provided [data] can be parsed by this suite.
  bool canParse(Object data);

  /// Parses the [data] into a verifiable credential.
  ///
  /// Throws an exception if the [data] cannot be converted to a valid
  /// [VerifiableCredential].
  ///
  /// Note: Implementers must check if the input can be parsed by this
  /// suite before attempting to parse.
  ParsedVC parse(Object data);

  /// Verifies the cryptographic integrity of the [input] credential.
  Future<bool> verifyIntegrity(ParsedVC input);

  /// Issues a new credential by signing the [vc] with the provided [signer].
  ///
  /// Returns a parsed verifiable credential with the appropriate signature.
  /// Optional [options] can customize the issuing process.
  Future<ParsedVC> issue(
    VC vc,
    DidSigner signer, {
    Options? options,
  });

  dynamic present(ParsedVC input);
}
