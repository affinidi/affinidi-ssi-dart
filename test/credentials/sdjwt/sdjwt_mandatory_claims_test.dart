import 'dart:typed_data';

import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  group('SD-JWT Mandatory Claims Validation Tests', () {
    final testSeed =
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    late DidSigner signer;
    late SdJwtDm2Suite suite;

    setUp(() async {
      signer = await initSigner(testSeed);
      suite = SdJwtDm2Suite();
    });

    group('Mandatory Field Disclosure Validation', () {
      test('should fail when @context is made selectively disclosable',
          () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
        );

        // Attempt to make @context selectively disclosable (this should fail)
        final invalidDisclosureFrame = {
          '_sd': ['@context'], // This violates the spec
        };

        // This should either throw an exception or the verification should fail
        expect(
          () async => await suite.issue(
            unsignedData: VcDataModelV2.fromMutable(credential),
            signer: signer,
            disclosureFrame: invalidDisclosureFrame,
          ),
          throwsA(isA<SsiException>()),
        );
      });

      test('should fail when type is made selectively disclosable', () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
        );

        // Attempt to make type selectively disclosable (this should fail)
        final invalidDisclosureFrame = {
          '_sd': ['type'], // This violates the spec
        };

        expect(
          () async => await suite.issue(
            unsignedData: VcDataModelV2.fromMutable(credential),
            signer: signer,
            disclosureFrame: invalidDisclosureFrame,
          ),
          throwsA(isA<SsiException>()),
        );
      });

      test('should fail when credentialSchema is made selectively disclosable',
          () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
          credentialSchema: [
            MutableCredentialSchema(
              id: Uri.parse('https://example.org/schema.json'),
              type: 'JsonSchema',
            ),
          ],
        );

        // Attempt to make credentialSchema selectively disclosable (this should fail)
        final invalidDisclosureFrame = {
          '_sd': ['credentialSchema'], // This violates the spec
        };

        expect(
          () async => await suite.issue(
            unsignedData: VcDataModelV2.fromMutable(credential),
            signer: signer,
            disclosureFrame: invalidDisclosureFrame,
          ),
          throwsA(isA<SsiException>()),
        );
      });

      test('should fail when credentialStatus is made selectively disclosable',
          () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
          credentialStatus: [
            MutableCredentialStatusV2({
              'id': Uri.parse('https://example.org/status/1'),
              'type': 'StatusList2021Entry',
              'statusPurpose': 'revocation',
              'statusListIndex': '12345',
              'statusListCredential': 'https://example.org/status-list',
            }),
          ],
        );

        // Attempt to make credentialStatus selectively disclosable (this should fail)
        final invalidDisclosureFrame = {
          '_sd': ['credentialStatus'], // This violates the spec
        };

        expect(
          () async => await suite.issue(
            unsignedData: VcDataModelV2.fromMutable(credential),
            signer: signer,
            disclosureFrame: invalidDisclosureFrame,
          ),
          throwsA(isA<SsiException>()),
        );
      });

      test('should allow other fields to be selectively disclosable', () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
              'age': 30,
              'email': 'test@example.com',
            })
          ],
        );

        // Making non-mandatory fields selectively disclosable should be allowed
        final validDisclosureFrame = {
          'credentialSubject': {
            '_sd': ['age', 'email'], // Non-mandatory fields
          },
        };

        final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential),
          signer: signer,
          disclosureFrame: validDisclosureFrame,
        );

        expect(issuedCredential, isNotNull);
        expect(issuedCredential.serialized, contains('~'));

        final isValid = await suite.verifyIntegrity(issuedCredential);
        expect(isValid, isTrue);
      });
    });

    group('Verification of Disclosed Claims', () {
      test('should verify that @context is always present in payload',
          () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
        );

        final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential),
          signer: signer,
        );

        // @context must be present in the payload (not in disclosures)
        expect(issuedCredential.sdJwt.payload, contains('@context'));
        expect(issuedCredential.context, isNotNull);
      });

      test('should verify that type is always present in payload', () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
        );

        final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential),
          signer: signer,
        );

        // type must be present in the payload (not in disclosures)
        expect(issuedCredential.sdJwt.payload, contains('type'));
        expect(issuedCredential.type, isNotNull);
        expect(issuedCredential.type, contains('VerifiableCredential'));
      });

      test(
          'should verify that credentialSchema is present in payload when provided',
          () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
          credentialSchema: [
            MutableCredentialSchema(
              id: Uri.parse('https://example.org/schema.json'),
              type: 'JsonSchema',
            ),
          ],
        );

        final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential),
          signer: signer,
        );

        // credentialSchema must be present in the payload (not in disclosures)
        expect(issuedCredential.sdJwt.payload, contains('credentialSchema'));
        expect(issuedCredential.credentialSchema, isNotEmpty);
      });

      test(
          'should verify that credentialStatus is present in payload when provided',
          () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
          credentialStatus: [
            MutableCredentialStatusV2({
              'id': Uri.parse('https://example.org/status/1'),
              'type': 'StatusList2021Entry',
              'statusPurpose': 'revocation',
              'statusListIndex': '12345',
              'statusListCredential': 'https://example.org/status-list',
            }),
          ],
        );

        final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential),
          signer: signer,
        );

        // credentialStatus must be present in the payload (not in disclosures)
        expect(issuedCredential.sdJwt.payload, contains('credentialStatus'));
        expect(issuedCredential.credentialStatus, isNotEmpty);
      });
    });

    group('Edge Cases', () {
      test('should handle credentials without optional mandatory fields',
          () async {
        // Credential without credentialSchema and credentialStatus
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
        );

        final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential),
          signer: signer,
        );

        expect(issuedCredential, isNotNull);
        expect(issuedCredential.sdJwt.payload, contains('@context'));
        expect(issuedCredential.sdJwt.payload, contains('type'));

        final isValid = await suite.verifyIntegrity(issuedCredential);
        expect(isValid, isTrue);
      });

      test(
          'should prevent nested fields of mandatory claims from being selectively disclosable',
          () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
          credentialSchema: [
            MutableCredentialSchema(
              id: Uri.parse('https://example.org/schema.json'),
              type: 'JsonSchema',
            ),
          ],
        );

        // Attempt to make nested properties of credentialSchema selectively disclosable
        final invalidDisclosureFrame = {
          'credentialSchema': {
            '_sd': ['id', 'type'], // Nested properties should also not be SD
          },
        };

        // This should fail because credentialSchema and its contents must be fully disclosed
        expect(
          () async => await suite.issue(
            unsignedData: VcDataModelV2.fromMutable(credential),
            signer: signer,
            disclosureFrame: invalidDisclosureFrame,
          ),
          throwsA(isA<SsiException>()),
        );
      });

      test('should validate that issuer is always disclosed', () async {
        final credential = MutableVcDataModelV2(
          context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
          id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
          issuer: Issuer.uri(signer.did),
          type: {'VerifiableCredential', 'TestCredential'},
          validFrom: DateTime.parse('2023-01-01T12:00:00Z'),
          credentialSubject: [
            MutableCredentialSubject({
              'id': 'did:example:subject',
              'name': 'Test Subject',
            })
          ],
        );

        final issuedCredential = await suite.issue(
          unsignedData: VcDataModelV2.fromMutable(credential),
          signer: signer,
        );

        // issuer must be present in the payload
        expect(issuedCredential.sdJwt.payload, contains('issuer'));
        expect(issuedCredential.issuer, isNotNull);
      });
    });
  });
}
