import 'package:sdjwt_sdk/sdjwt_sdk.dart';

import '../base/action.dart';

/// Extractor for creating confirmation (cnf) claims from public keys.
///
/// A confirmation claim (cnf) is a JWT claim that binds a key to the token,
/// enabling proof-of-possession. This is defined in the Internet Draft:
/// https://datatracker.ietf.org/doc/html/rfc7800
///
/// This class extracts the necessary information from a public key to create
/// a confirmation claim that can be included in a JWT to enable key binding.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class CnfExtractor extends Action<SdPublicKey, Map<String, dynamic>> {
  @override
  Map<String, dynamic> execute(SdPublicKey input) {
    return {'jwk': input.toJson()};
  }
}
