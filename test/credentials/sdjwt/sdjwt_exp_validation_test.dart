import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SD-JWT VC Data Model V2 - exp validation', () {
    final testSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    late DidSigner signer;
    late SdJwtDm2Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = SdJwtDm2Suite();
    });

    test('verifyIntegrity should return true when exp is not present',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-no-exp',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'credentialSubject': {'email': 'test@example.com'},
      })..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      // Verify with current time - should be valid since no exp
      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isTrue);
    });

    test('verifyIntegrity should return true when current time is before exp',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-valid',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'validUntil': '2025-12-31T23:59:59Z',
        'credentialSubject': {'email': 'test@example.com'},
      })..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      // Verify with time before expiration
      final isValid = await suite.verifyIntegrity(
        issuedCredential,
        getNow: () => DateTime.parse('2025-06-15T12:00:00Z'),
      );
      expect(isValid, isTrue);
    });

    test('verifyIntegrity should return false when current time is after exp',
        () async {
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-expired',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'validUntil': '2024-12-31T23:59:59Z',
        'credentialSubject': {'email': 'test@example.com'},
      })..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

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
      final credential = MutableVcDataModelV2.fromJson({
        '@context': [dmV2ContextUrl],
        'id': 'urn:uuid:test-credential-exact-exp',
        'type': ['VerifiableCredential', 'TestCredential'],
        'validFrom': '2023-01-01T12:00:00Z',
        'validUntil': expirationDate.toIso8601String(),
        'credentialSubject': {'email': 'test@example.com'},
      })..issuer = Issuer.uri(signer.did);

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

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

