import 'dart:convert';

import 'package:sdjwt_sdk/src/models/sdjwt.dart';

import '../base/action.dart';
import '../utils/cnf_extractor.dart';

/// Validator for Key Binding JWT signer input.
///
/// This class validates that the input for the KB-JWT signing process is valid,
/// checking that all disclosures to keep are present in the SD-JWT and that
/// the holder public key matches the cnf claim in the SD-JWT.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class AsyncKbJwtSignerInputValidator
    extends Action<KbJwtSignerInput, (String, Map<String, dynamic>)> {
  /// Extractor for confirmation claims.
  final _cnfExtractor = CnfExtractor();

  @override
  (String, Map<String, dynamic>) execute(KbJwtSignerInput input) {
    final sdJwt = input.sdJwtToken;

    final sdJwtStatus = sdJwt.isVerified;
    if (sdJwtStatus != true) {
      throw Exception(
          'The provided SdJwt must be verified before generating the kbJwt for it');
    }

    // valid for kb-sign
    if (!sdJwt.disclosures.containsAll(input.disclosuresToKeep)) {
      throw Exception(
          "Invalid SD-JWT: not all disclosuresToKeep are in sdJwtWithDisclosure");
    }

    if (input.holderPublicKey != null) {
      final cnf = _cnfExtractor.execute(input.holderPublicKey!);
      if (sdJwt.claims['cnf'] == null ||
          jsonEncode(cnf) != jsonEncode(sdJwt.claims['cnf'])) {
        throw Exception(
            '`cnf` is invalid or missing in issuerToken, it must match holder public key');
      }
    }

    return (sdJwt.serialized, sdJwt.claims);
  }
}
