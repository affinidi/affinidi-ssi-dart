part of 'sdjwt.dart';

/// A class representing the verification status of a [SdJwt].
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.

/// Example:
/// ```dart
/// final sdJwt = SdJwt.parse('...');
/// print(sdJwt.isVerified); // this prints false
///
/// final SdJwtHandler handler = SdJwtHandlerV1();
/// final verified = await handler.verify(
///   sdJwt: sdJwt,
///   verifier: verifier,
/// );
///
/// print(verified.sdJwt.isVerified); // prints the verification status
///
/// ```
@immutable
class SdJwtStatus {
  /// the key used to store the status of the sd-jwt's jws verification
  static const isJwsVerifiedKey = 'jwsVerified';

  /// the key used to store the status of kbJwt verification
  static const isKbJwtVerifiedKey = 'kbJwtVerified';

  /// the key tracking whether the sdJwt has kbJwt
  static const hasKbJwtKey = 'hasKbJwt';

  /// Map storing various statuses
  final Map<String, bool?> _statusMap;

  /// Initializes the status with defaults
  ///
  /// Parameters:
  /// -**[hasKbJwt]**: (required) if the sdJwt has the kbJwt. This is used in computing final verification status
  ///
  SdJwtStatus({required bool hasKbJwt}) : _statusMap = {hasKbJwtKey: hasKbJwt};

  /// Whether the jws in the sdJwt is verified. `null` if the jws was never verified.
  bool? get isJwsVerified => _statusMap[isJwsVerifiedKey];
  set _isJwsVerified(bool? status) => _statusMap[isJwsVerifiedKey] = status;

  /// Whether the kbJwt is verified. `null` if the kbJwt was never verified.
  bool? get isKbJwtVerified => _statusMap[isKbJwtVerifiedKey];
  set _isKbJwtVerified(bool? status) => _statusMap[isKbJwtVerifiedKey] = status;

  /// Whether the sdJwt has kbJwt in it
  bool get hasKbJwt => _statusMap[hasKbJwtKey] ?? false;

  /// Whether the sdJwt can be considered as Verified. The value of this can be interpreted as follows:
  ///   null => the sdjwt has never been verified.
  ///   false => the sdjwt was verified but it failed the verification.
  ///   true => the sdjwt was verified and it succeeded the verification.
  bool? get isVerified {
    final jwsStatus = isJwsVerified;
    final kbJwtPresent = hasKbJwt;
    final kbJwtStatus = isKbJwtVerified;

    if (jwsStatus == null) return null;
    if (!kbJwtPresent) return jwsStatus;

    if (kbJwtStatus == null) return null;

    return jwsStatus && kbJwtStatus;
  }
}
