import '../../did/did_signer.dart';
import '../models/parsed_vc.dart';
import '../models/verifiable_credential.dart';

/// Class that contains operations to be done on encoded VCs
abstract interface class VerifiableCredentialSuite<
    SerializedType,
    VCDM extends VerifiableCredential,
    PVC extends ParsedVerifiableCredential<SerializedType>,
    Options> {
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  bool canParse(Object data);

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  ///
  /// Note: Implementers must check if the input can be parsed by the
  /// implementing suite
  PVC parse(Object data);

  /// Verify the integrity of [input]
  Future<bool> verifyIntegrity(PVC input);

  /// Prepare an Encoded VC based on the
  Future<PVC> issue(
    VCDM vp,
    DidSigner signer, {
    Options? options,
  });
}
