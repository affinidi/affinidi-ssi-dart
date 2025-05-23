import 'dart:convert';
import 'dart:developer' as developer;

import 'verifiable_data_parser.dart';

/// Mixin that provides functionality for parsing JSON-LD formatted data.
///
/// Implements the [VerifiableDataParser] interface for JSON-LD documents,
/// providing methods to check if a string is valid JSON-LD and to decode
/// it into a map structure.
mixin LdParser implements VerifiableDataParser<String, Map<String, dynamic>> {
  /// Validates whether the decoded [data] has the required structure.
  ///
  /// Implementers should override this method to check if the parsed
  /// JSON data meets specific requirements for their use case.
  bool hasValidPayload(Map<String, dynamic> data);

  @override
  bool canDecode(String input) => tryDecode(input) != null;

  @override
  Map<String, dynamic> decode(String input) =>
      jsonDecode(input) as Map<String, dynamic>;

  @override
  Map<String, dynamic>? tryDecode(String input) {
    // filter out JWT tokens
    if (input.startsWith('ey')) return null;

    try {
      final data = jsonDecode(input) as Map<String, dynamic>;
      if (!hasValidPayload(data)) return null;
      return data;
    } catch (e) {
      developer.log(
        'LdParser jsonDecode failed',
        level: 500, // FINE
      );
      return null;
    }
  }
}
