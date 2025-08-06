// ignore_for_file: avoid_print

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:ssi/src/credentials/presentations/presentations.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  Future<Map<String, dynamic>?> defaultDocumentLoader(Uri uri) async {
    try {
      final response = await http.get(
        uri,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
      ).timeout(Duration(seconds: 30));

      if (response.statusCode == 200) {
        final result = jsonDecode(response.body);
        return result as Map<String, dynamic>;
      }

      throw Exception('Failed to fetch document: ${response.statusCode}');
    } catch (e) {
      return null;
    }
  }

  group('Universal Presentation Verifier', () {
    test(
        'should be able to verify the revoked credential inside of a valid V1 presentation',
        () async {
      final v2Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithRevokedVCString);
      final verificationStatus = await UniversalPresentationVerifier(
              customDocumentLoader: defaultDocumentLoader)
          .verify(v2Vp);

      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, false);
    });
  });
}
