import 'dart:convert';

import 'package:ssi/src/credentials/parsers/verifiable_data_parser.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/src/exceptions/ssi_exception_type.dart';
import 'package:ssi/src/util/base64_util.dart';

class JWS {
  Map<String, dynamic> header;
  Map<String, dynamic> payload;
  String signature;
  String serialized;

  JWS(
      {required this.header,
      required this.payload,
      required this.signature,
      required this.serialized});
}

mixin JwtParser implements VerifiableDataParser<String, JWS> {
  @override
  canDecode(input) {
    return input.startsWith('ey') &&
        input.split('.').length == 3 &&
        input.split('~').length == 1;
  }

  @override
  decode(input) {
    final segments = input.split('.');

    if (segments.length != 3) {
      throw SsiException(
        message: 'Invalid JWT',
        code: SsiExceptionType.invalidVC.code,
      );
    }

    final Map<String, dynamic> header = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(segments[0]),
      ),
    );

    final Map<String, dynamic> payload = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(segments[1]),
      ),
    );

    return JWS(
        header: header,
        payload: payload,
        signature: segments[2],
        serialized: input);
  }
}
