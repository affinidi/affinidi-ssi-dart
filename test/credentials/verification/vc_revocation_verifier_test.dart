import 'dart:convert';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('RevocationList2020 Verifier', () {
    test('Should pass for non-revoked credential', () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async =>
            VerifiableCredentialDataFixtures.revocationListCredential,
      );

      final data =
          VerifiableCredentialDataFixtures.credentialWithNonRevokedStatusString;
      final parsed = UniversalParser.parse(data);
      final result = await verifier.verify(parsed);

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test('Should fail for revoked credential', () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async =>
            VerifiableCredentialDataFixtures.revocationListCredential,
      );

      final data =
          VerifiableCredentialDataFixtures.credentialWithRevokedStatusString;
      final parsed = UniversalParser.parse(data);
      final result = await verifier.verify(parsed);

      expect(result.isValid, false);
      expect(
          result.errors,
          contains(
              '${SsiExceptionType.revokedVC.code} ${parsed.id} for status urn:uuid:revocation-list-0'));
      expect(result.warnings, isEmpty);
    });

    test('Should pass if credentialStatus is missing', () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async =>
            VerifiableCredentialDataFixtures.revocationListCredential,
      );

      final map = jsonDecode(VerifiableCredentialDataFixtures
          .credentialWithNonRevokedStatusString);
      map.remove('credentialStatus');
      ParsedVerifiableCredential? vc;
      vc = UniversalParser.parse(jsonEncode(map));

      final result = await verifier.verify(vc);

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test('Should fail if revocationListCredential is invalid', () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (uri) async {
          if (!['http', 'https'].contains(uri.scheme)) {
            throw Exception('Invalid URL scheme');
          }
          return VerifiableCredentialDataFixtures.revocationListCredential;
        },
      );
      final map = jsonDecode(VerifiableCredentialDataFixtures
          .credentialWithNonRevokedStatusString);
      map['credentialStatus']['revocationListCredential'] = 'invalid-url';
      final parsed = UniversalParser.parse(jsonEncode(map));
      final result = await verifier.verify(parsed);

      expect(result.isValid, false);
      expect(
        result.errors,
        contains(
            '${SsiExceptionType.failedToFetchRevocationList.code} for VC ${parsed.id} status urn:uuid:revocation-list-0: Exception: Invalid URL scheme'),
      );
      expect(result.warnings, isEmpty);
    });

    test('Should fail if revocationListIndex is invalid', () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async =>
            VerifiableCredentialDataFixtures.revocationListCredential,
      );

      final map = jsonDecode(VerifiableCredentialDataFixtures
          .credentialWithNonRevokedStatusString);
      map['credentialStatus']['revocationListIndex'] = 'invalid-index';
      final parsed = UniversalParser.parse(jsonEncode(map));
      final result = await verifier.verify(parsed);

      expect(result.isValid, false);
      expect(
        result.errors,
        contains(
            '${SsiExceptionType.invalidVC.code} ${parsed.id} for status urn:uuid:revocation-list-0'),
      );
      expect(result.warnings, isEmpty);
    });

    test('Should fail if fetching revocation list fails', () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async =>
            throw Exception('Network error'),
      );

      final data =
          VerifiableCredentialDataFixtures.credentialWithNonRevokedStatusString;
      final parsed = UniversalParser.parse(data);
      final result = await verifier.verify(parsed);

      expect(result.isValid, false);
      expect(
        result.errors,
        contains(
            '${SsiExceptionType.failedToFetchRevocationList.code} for VC ${parsed.id} status urn:uuid:revocation-list-0: Exception: Network error'),
      );
      expect(result.warnings, isEmpty);
    });

    test('Should fail if encodedList is invalid', () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async {
          final revocationList = Map<String, dynamic>.from(
              VerifiableCredentialDataFixtures.revocationListCredential);
          revocationList['credentialSubject']['encodedList'] = 'invalid-base64';
          return revocationList;
        },
      );

      final data =
          VerifiableCredentialDataFixtures.credentialWithNonRevokedStatusString;
      final parsed = UniversalParser.parse(data);
      final result = await verifier.verify(parsed);

      expect(result.isValid, false);
      expect(
        result.errors,
        contains(
            '${SsiExceptionType.invalidEncoding.code} for VC ${parsed.id} status urn:uuid:revocation-list-0'),
      );
      expect(result.warnings, isEmpty);
    });

    test('Should fail if revocation index is out of bounds', () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async =>
            VerifiableCredentialDataFixtures.revocationListCredential,
      );

      final map = jsonDecode(VerifiableCredentialDataFixtures
          .credentialWithNonRevokedStatusString);
      map['credentialStatus']['revocationListIndex'] = '1000000';
      final parsed = UniversalParser.parse(jsonEncode(map));
      final result = await verifier.verify(parsed);

      expect(result.isValid, false);
      expect(
        result.errors,
        contains(
            '${SsiExceptionType.revocationIndexOutOfBounds.code} for VC ${parsed.id} status urn:uuid:revocation-list-0'),
      );
      expect(result.warnings, isEmpty);
    });
    test('Should pass for V2 credential with multiple non-revoked statuses',
        () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async =>
            VerifiableCredentialDataFixtures.revocationListCredential,
      );

      ParsedVerifiableCredential? vc;
      try {
        vc = UniversalParser.parse(VerifiableCredentialDataFixtures
            .credentialWithMultipleNonRevokedStatusV2String);
      } catch (e) {
        fail('Failed to parse VC: $e');
      }

      final result = await verifier.verify(vc);

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });
    test(
        'Should fail for V2 credential with mixed revoked/non-revoked statuses',
        () async {
      final verifier = RevocationList2020Verifier(
        fetchStatusListCredential: (_) async =>
            VerifiableCredentialDataFixtures.revocationListCredential,
      );

      final vc = UniversalParser.parse(
          VerifiableCredentialDataFixtures.credentialWithMixedStatusV2String);
      final result = await verifier.verify(vc);

      expect(result.isValid, false);
      expect(
          result.errors,
          contains(
              '${SsiExceptionType.revokedVC.code} ${vc.id} for status urn:uuid:revocation-list-1'));
      expect(result.warnings, isEmpty);
    });

    test(
        'Should fail parsing V2 credential with more than 5 credentialStatus items',
        () {
      final statusList = List.generate(
        6,
        (i) => {
          'id': 'urn:uuid:revocation-list-$i',
          'type': 'RevocationList2020Status',
          'revocationListIndex': '$i',
          'revocationListCredential':
              'https://example.edu/status/revocation-list',
        },
      );

      final vcJson = {
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential',
        'type': ['VerifiableCredential'],
        'issuer': {'id': 'did:example:issuer'},
        'validFrom': DateTime.now().toIso8601String(),
        'credentialSubject': {'id': 'did:example:subject'},
        'credentialStatus': statusList,
      };

      // Test parsing directly with VcDataModelV2 - this is where the validation happens
      expect(
        () => VcDataModelV2.fromJson(vcJson),
        throwsA(predicate((e) =>
            e is SsiException &&
            e.code == SsiExceptionType.invalidJson.code &&
            e.message.contains('must not exceed 5 items'))),
      );
    });

    test('Should accept V2 credential with exactly 5 credentialStatus items',
        () {
      final statusList = List.generate(
        5,
        (i) => {
          'id': 'urn:uuid:revocation-list-$i',
          'type': 'RevocationList2020Status',
          'revocationListIndex': '$i',
          'revocationListCredential':
              'https://example.edu/status/revocation-list',
        },
      );

      final vcJson = {
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential',
        'type': ['VerifiableCredential'],
        'issuer': {'id': 'did:example:issuer'},
        'validFrom': DateTime.now().toIso8601String(),
        'credentialSubject': {'id': 'did:example:subject'},
        'credentialStatus': statusList,
      };

      // Test parsing directly with VcDataModelV2 - this should succeed
      final vc = VcDataModelV2.fromJson(vcJson);
      expect(vc.credentialStatus.length, 5);
    });
  });
}
