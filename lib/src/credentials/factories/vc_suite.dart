import 'package:ssi/src/credentials/models/verifiable_credential.dart';
import 'package:ssi/src/credentials/models/verifiable_data.dart';
import 'package:ssi/src/did/did_signer.dart';

/// Class that contains operations to be done on encoded VCs
abstract class VerifiableCredentialSuite<SerializedType,
    VDM extends VerifiableData, PDM extends VDM, Options> {
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  bool canParse(Object data);

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  ///
  /// Note: Implementers must check if the input can be parsed by the
  /// implementing suite
  PDM parse(Object data);

  /// Verify the integrity of [input]
  Future<bool> verifyIntegrity(PDM input);

  /// Prepare an Encoded VC based on the
  Future<PDM> issue(
    VDM vd,
    DidSigner signer, {
    Options? options,
  });
}
