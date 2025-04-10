import 'dart:convert';
import 'dart:developer' as developer;

import 'package:ssi/src/credentials/parsers/verifiable_data_parser.dart';

mixin LdParser implements VerifiableDataParser<String, Map<String, dynamic>> {
  bool hasValidPayload(Map<String, dynamic> data);

  @override
  canDecode(input) {
    // filter out JWT tokens
    if (input.startsWith('ey')) return false;

    // FIXME(cm) decoding twice in canParse and parse
    Map<String, dynamic> data;
    try {
      data = jsonDecode(input);
    } catch (e) {
      developer.log(
        "LdBaseSuite jsonDecode failed",
        level: 500, // FINE
      );
      return false;
    }

    if (!hasValidPayload(data)) return false;

    return true;
  }

  @override
  decode(input) {
    return jsonDecode(input);
  }
}
