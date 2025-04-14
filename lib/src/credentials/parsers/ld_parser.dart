import 'dart:convert';
import 'dart:developer' as developer;

import 'verifiable_data_parser.dart';

mixin LdParser implements VerifiableDataParser<String, Map<String, dynamic>> {
  bool hasValidPayload(Map<String, dynamic> data);

  @override
  bool canDecode(String input) {
    // filter out JWT tokens
    if (input.startsWith('ey')) return false;

    try {
      final data = jsonDecode(input) as Map<String, dynamic>;
      if (!hasValidPayload(data)) return false;
    } catch (e) {
      developer.log(
        'LdParser jsonDecode failed',
        level: 500, // FINE
      );
      return false;
    }

    return true;
  }

  @override
  Map<String, dynamic> decode(String input) {
    return jsonDecode(input) as Map<String, dynamic>;
  }
}
