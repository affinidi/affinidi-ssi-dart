import 'dart:developer' as developer;

import 'package:sdjwt/sdjwt.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import 'verifiable_data_parser.dart';

/// Mixin that provides functionality for parsing SD-JWT formatted data.
///
/// Implements the [VerifiableDataParser] interface for Selective Disclosure JWTs,
/// providing methods to check if a string is a valid SD-JWT and to decode
/// it into its component parts.
mixin SdJwtParser implements VerifiableDataParser<String, SdJwt> {
  /// Validates whether the decoded [data] has the required structure.
  ///
  /// Implementers should override this method to check if the parsed
  /// SD-JWT meets specific requirements for their use case.
  bool hasValidPayload(SdJwt data);

  @override
  bool canDecode(String input) {
    // filter out other strings
    if (!input.startsWith('ey')) return false;

    try {
      final jwt = SdJwt.parse(input);
      if (!hasValidPayload(jwt)) return false;
    } catch (e) {
      developer.log(
        'SdJwt decode failed',
        level: 500, // FINE
        error: e,
      );
      return false;
    }

    return true;
  }

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
