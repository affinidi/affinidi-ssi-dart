import 'dart:developer' as developer;

import 'package:selective_disclosure_jwt/selective_disclosure_jwt.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import 'verifiable_data_parser.dart';

/// Mixin that provides functionality for parsing SD-JWT formatted data.
///
/// Implements the [VerifiableDataParser] interface for Selective Disclosure JWTs,
/// providing methods to check if a string is a valid SD-JWT and to decode
/// it into its component parts.
mixin SdJwtParser implements VerifiableDataParser<String, SdJwt> {
  /// Validates whether the decoded data has the required structure.
  ///
  /// [data] - The decoded SD-JWT to validate.
  ///
  /// Returns true if the SD-JWT payload contains the required fields
  /// for the implementing class's specific credential format.
  ///
  /// Implementers should override this method to check if the parsed
  /// SD-JWT meets specific requirements for their use case.
  bool hasValidPayload(SdJwt data);

  /// Checks if the provided input can be decoded as an SD-JWT.
  ///
  /// [input] - The string to check for SD-JWT format.
  ///
  /// Returns true if the input is a valid SD-JWT with a payload
  /// that matches the requirements defined in [hasValidPayload].
  @override
  bool canDecode(String input) {
    if (!input.startsWith('ey')) return false;

    try {
      final jwt = SdJwt.parse(input);
      return hasValidPayload(jwt);
    } catch (e) {
      developer.log('Failed to decode SD-JWT: $e');
      return false;
    }
  }

  /// Decodes the input string into an SD-JWT structure.
  ///
  /// [input] - The string to decode as an SD-JWT.
  ///
  /// Returns the parsed SD-JWT structure if successful.
  ///
  /// Throws [SsiException] if the input is not a valid SD-JWT format.
  @override
  SdJwt decode(String input) {
    // filter out other strings
    if (!input.startsWith('ey')) {
      throw SsiException(
        message: 'Not a SDJWT',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    return SdJwt.parse(input);
  }
}
