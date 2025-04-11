import 'dart:convert';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../util/base64_util.dart';
import 'verifiable_data_parser.dart';

class Jws {
  Map<String, dynamic> header;
  Map<String, dynamic> payload;
  String signature;
  String serialized;

  Jws(
      {required this.header,
      required this.payload,
      required this.signature,
      required this.serialized});
}

mixin JwtParser implements VerifiableDataParser<String, Jws> {
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

    final header = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(segments[0]),
      ),
    ) as Map<String, dynamic>;

    final payload = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(segments[1]),
      ),
    ) as Map<String, dynamic>;

    return Jws(
        header: header,
        payload: payload,
        signature: segments[2],
        serialized: input);
  }
}
