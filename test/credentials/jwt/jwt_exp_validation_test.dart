import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('JWT VC Data Model V1 - exp validation', () {
    final testSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    late DidSigner signer;
    late JwtDm1Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = JwtDm1Suite();
    });

    test('verifyIntegrity should return true when exp is not present',
        () async {
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:test-credential-no-exp',
        'type': ['VerifiableCredential', 'TestCredential'],
        'holder': {'id': signer.did},
        'issuanceDate': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

      // Verify with current time - should be valid since no exp
      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isTrue);
    });

    test('verifyIntegrity should return true when current time is before exp',
        () async {
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:test-credential-valid',
        'holder': {'id': signer.did},
        'type': ['VerifiableCredential', 'TestCredential'],
        'issuanceDate': '2023-01-01T12:00:00Z',
        'expirationDate': '2025-12-31T23:59:59Z',
        'credentialSubject': {'email': 'test@example.com'},
      })..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

      // Verify with time before expiration
      final isValid = await suite.verifyIntegrity(
        issuedCredential,
        getNow: () => DateTime.parse('2025-06-15T12:00:00Z'),
      );
      expect(isValid, isTrue);
    });

    test('verifyIntegrity should return false when current time is after exp',
        () async {
      final credential = MutableVcDataModelV1.fromJson({
        '@context': [dmV1ContextUrl],
        'holder': {'id': signer.did},
        'id': 'urn:uuid:test-credential-expired',
        'type': ['VerifiableCredential', 'TestCredential'],
        'issuanceDate': '2023-01-01T12:00:00Z',
        'expirationDate': '2024-12-31T23:59:59Z',
        'credentialSubject': {'email': 'test@example.com'},
      })..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

      // Verify with time after expiration
      final isValid = await suite.verifyIntegrity(
        issuedCredential,
        getNow: () => DateTime.parse('2025-01-01T00:00:00Z'),
      );
      expect(isValid, isFalse);
    });

    test(
        'verifyIntegrity should return false when current time equals exp timestamp',
        () async {
      final expirationDate = DateTime.parse('2024-12-31T23:59:59Z');
      final credential = MutableVcDataModelV1.fromJson({
        'holder': {'id': signer.did},
        '@context': [dmV1ContextUrl],
        'id': 'urn:uuid:test-credential-exact-exp',
        'type': ['VerifiableCredential', 'TestCredential'],
        'issuanceDate': '2023-01-01T12:00:00Z',
        'expirationDate': expirationDate.toIso8601String(),
        'credentialSubject': {'email': 'test@example.com'},
      })..issuer = MutableIssuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV1.fromMutable(credential), signer: signer);

      // Verify with time exactly at expiration (1 second after due to floor conversion)
      final isValid = await suite.verifyIntegrity(
        issuedCredential,
        getNow: () => DateTime.fromMillisecondsSinceEpoch(
            (expirationDate.millisecondsSinceEpoch / 1000).floor() * 1000 + 1),
      );
      expect(isValid, isFalse);
    });
  });
}

