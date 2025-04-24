import 'dart:convert';
import 'utils.dart';

class FromPriorJWT {
  final String typ = 'JWT';
  late String sub;
  late String iss;
  late DateTime iat;
  late String kid;
  late String alg;
  late String curve;
  late String signature;

  FromPriorJWT(
      {required this.sub,
      required this.iss,
      required this.iat,
      required this.curve,
      required this.alg,
      required this.kid,
      required this.signature});

  FromPriorJWT.fromCompactSerialization(String jwtCompact) {
    var splitted = jwtCompact.split('.');
    if (splitted.length != 3) {
      throw FormatException(
          'compact serialization must consist of three parts separated by point(.).');
    }
    Map<String, dynamic> header =
        jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(splitted[0]))));
    Map<String, dynamic> payload =
        jsonDecode(utf8.decode(base64Decode(addPaddingToBase64(splitted[1]))));
    signature = splitted[2];

    if (header['typ'] != typ) throw FormatException('typ value must be JWT');
    alg = header['alg'];
    curve = header['crv'];
    kid = header['kid'];

    sub = payload['sub']!;
    iss = payload['iss']!;
    iat =
        DateTime.fromMillisecondsSinceEpoch(payload['iat'] * 1000, isUtc: true);

    //TODO: check signature
  }
}
