import 'dart:convert';

import 'package:ssi/ssi.dart';

/// Parses a [ParsedVerifiableCredential] from JSON or string input.
///
/// Accepts either a raw credential object or its serialized string form.
/// Delegates to [UniversalParser].
ParsedVerifiableCredential parseVC(dynamic e) {
  String encoded;
  if (e is! String) {
    encoded = jsonEncode(e);
  } else {
    encoded = e;
  }

  return UniversalParser.parse(encoded);
}

/// Converts a [ParsedVerifiableCredential] into its presentable form
/// using the appropriate VC suite.
dynamic presentVC(ParsedVerifiableCredential credential) {
  final suite = VcSuites.getVcSuite(credential);
  final present = suite.present(credential);

  if (present is! String && present is! Map<String, dynamic>) {
    return credential.toJson();
  }

  return present;
}
