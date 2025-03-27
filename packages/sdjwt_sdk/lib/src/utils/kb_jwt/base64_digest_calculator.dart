import 'package:sdjwt_sdk/src/base/action.dart';
import 'package:sdjwt_sdk/src/models/sdjwt.dart';

/// Calculator for creating base64-encoded digest for [SdJwt] .
///
/// This class calculates a digest of an [SdJwt] which is used in the key binding process
/// to bind the SD-JWT to a specific holder.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
class Base64DigestCalculator extends Action<SdJwt, String> {
  @override
  String execute(SdJwt input) {
    return input.hasher.execute(input.serialized);
  }
}
