import 'package:ssi/src/credentials/presentations/models/parsed_vp.dart';

import '../../../did/did_signer.dart';
import '../models/verifiable_presentation.dart';

/// Class that contains operations to be done on encoded VCs
abstract class VerifiablePresentationSuite<
    SerializedType,
    VPDM extends VerifiablePresentation,
    PVP extends ParsedVerifiablePresentation<SerializedType>,
    Options> {
  /// Checks if the [data] provided matches the right criteria to attempt a parse
  bool canParse(Object data);

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  ///
  /// Note: Implementers must check if the input can be parsed by the
  /// implementing suite
  PVP parse(Object data);

  /// Verify the integrity of [input]
  Future<bool> verifyIntegrity(PVP input);

  /// Prepare an Encoded VC based on the
  Future<PVP> issue(
    VPDM vp,
    DidSigner signer, {
    Options? options,
  });
}
