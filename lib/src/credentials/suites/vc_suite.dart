import '../../did/did_resolver.dart';
import '../models/parsed_vc.dart';
import '../models/verifiable_credential.dart';

/// Defines operations for working with encoded Verifiable Credentials.
abstract interface class VerifiableCredentialSuite<
    SerializedType,
    VC extends VerifiableCredential,
    ParsedVC extends ParsedVerifiableCredential<SerializedType>> {
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

  /// Attempts to parse the [data] and returns the result if successful, null otherwise.
  ///
  /// This method combines validation and parsing in one step to avoid redundant operations.
  ParsedVC? tryParse(Object data);

  /// Verifies the cryptographic integrity of the [input] credential.
  ///
  /// NOTE: only the signature is verified, other claims like `challenge` or
  /// `nonce` must be separately validated
  ///
  /// Optionally accepts a custom [didResolver] for resolving DID documents.
  Future<bool> verifyIntegrity(ParsedVC input,
      {DateTime Function() getNow = DateTime.now, DidResolver? didResolver});

  /// Presents the [input] credential in its serialized form.
  dynamic present(ParsedVC input);
}
