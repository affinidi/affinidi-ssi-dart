import 'dart:developer' as developer;

import 'package:sdjwt/sdjwt.dart';
import 'package:ssi/src/credentials/parsers/verifiable_data_parser.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';

mixin SdJwtParser implements VerifiableDataParser<String, SdJwt> {
  bool hasValidPayload(SdJwt data);

  @override
  canDecode(input) {
    // filter out other strings
    if (!input.startsWith('ey')) return false;

    // FIXME(cm) decoding twice in canParse and parse
    try {
      SdJwt jwt = SdJwt.parse(input);
      if (!hasValidPayload(jwt)) return false;
    } catch (e) {
      developer.log(
        "SdJwt decode failed",
        level: 500, // FINE
        error: e,
      );
      return false;
    }

    return true;
  }

  @override
  decode(input) {
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
