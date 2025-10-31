import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('LD Credential v1 Validation Tests', () {
    test('Throws when context is empty', () {
      final credentialWithEmptyContext = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptyContext),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when context does not include required URL', () {
      final credentialWithWrongContext = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson(
            ['https://www.w3.org/ns/credentials/v2']),
        // Wrong context URL
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithWrongContext),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when type is empty', () {
      final credentialWithEmptyType = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([dmV1ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptyType),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when type does not include VerifiableCredential', () {
      final credentialWithWrongType = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([dmV1ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'UniversityDegreeCredential'},
        // Missing VerifiableCredential type
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithWrongType),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when issuer is empty', () {
      final credentialWithEmptyIssuer = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([dmV1ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri(''),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({
            'id': 'did:example:subject',
            'name': 'John Doe',
          })
        ],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptyIssuer),
        throwsA(isA<SsiException>()),
      );
    });

    test('Throws when credentialSubject is empty', () {
      final credentialWithEmptySubject = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([dmV1ContextUrl]),
        id: Uri.parse('urn:uuid:1234abcd-1234-abcd-1234-abcd1234abcd'),
        issuer: MutableIssuer.uri('did:example:issuer'),
        type: {'VerifiableCredential'},
        credentialSubject: [],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithEmptySubject),
        throwsA(isA<SsiException>()),
      );
    });

    test('Reports multiple validation errors at once', () {
      final credentialWithMultipleErrors = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([]),
        issuer: MutableIssuer.uri(''),
        type: {},
        credentialSubject: [],
      );

      expect(
        () => VcDataModelV1.fromMutable(credentialWithMultipleErrors),
        throwsA(isA<SsiException>()),
      );
    });
  });
}
