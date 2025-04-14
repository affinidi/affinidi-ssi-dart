import 'dart:developer' as developer;

import 'package:sdjwt/sdjwt.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import 'verifiable_data_parser.dart';

mixin SdJwtParser implements VerifiableDataParser<String, SdJwt> {
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
