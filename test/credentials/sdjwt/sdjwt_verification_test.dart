import 'dart:typed_data';

import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SD-JWT Verification Tests', () {
    final testSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    late DidSigner signer;
    late SdJwtDm2Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = SdJwtDm2Suite();
    });

    test('verifies credential with valid time range', () async {
      final now = DateTime.now();
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'TestCredential'},
        validFrom: now.subtract(Duration(hours: 1)),
        validUntil: now.add(Duration(hours: 1)),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'Test Subject',
          })
        ],
      );

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isTrue);
    });

    test('fails verification for expired credential', () async {
      final now = DateTime.now();
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'TestCredential'},
        validFrom: now.subtract(Duration(hours: 2)),
        validUntil: now.subtract(Duration(hours: 1)), // Expired
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'Test Subject',
          })
        ],
      );

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isFalse);
    });

    test('fails verification for credential not yet valid', () async {
      final now = DateTime.now();
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'TestCredential'},
        validFrom: now.add(Duration(hours: 1)), // Not yet valid
        validUntil: now.add(Duration(hours: 2)),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'Test Subject',
          })
        ],
      );

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isFalse);
    });

    test('verifies credential without expiration', () async {
      final now = DateTime.now();
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'TestCredential'},
        validFrom: now.subtract(Duration(hours: 1)),
        // No validUntil
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'Test Subject',
          })
        ],
      );

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      final isValid = await suite.verifyIntegrity(issuedCredential);
      expect(isValid, isTrue);
    });

    test('can verify with custom time function', () async {
      final fixedTime = DateTime.parse('2023-06-01T12:00:00Z');
      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: Issuer.uri(signer.did),
        type: {'VerifiableCredential', 'TestCredential'},
        validFrom: DateTime.parse('2023-01-01T00:00:00Z'),
        validUntil: DateTime.parse('2023-12-31T23:59:59Z'),
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'Test Subject',
          })
        ],
      );

      final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential), signer: signer);

      final isValid = await suite.verifyIntegrity(issuedCredential,
          getNow: () => fixedTime);
      expect(isValid, isTrue);
    });
  });
}