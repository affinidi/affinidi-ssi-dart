import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/src/exceptions/ssi_exception.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/context_fixtures.dart';
import '../../test_utils.dart';

void main() {
  group('JsonLdContext', () {
    test('Single string URI context', () {
      final context = JsonLdContext.fromJson(['https://example.com/context']);
      expect(context.firstUri.toString(), 'https://example.com/context');
      expect(context.toJson(), ['https://example.com/context']);
      expect(context.hasUrlContext(Uri.parse('https://example.com/context')),
          isTrue);
    });

    test('List with string URIs', () {
      final context = JsonLdContext.fromJson(
          ['https://example.com/context', 'https://example.com/other']);
      expect(context.firstUri.toString(), 'https://example.com/context');
      expect(context.hasUrlContext(Uri.parse('https://example.com/other')),
          isTrue);
      expect(context.hasUrlContext(Uri.parse('https://not-in-context.com')),
          isFalse);
    });

    test('List with first element as a map throws exception (VC compliance)',
        () {
      expect(
          () => JsonLdContext.fromJson([
                {'@vocab': 'https://schema.org/'},
                'https://example.com/context'
              ]),
          throwsA(isA<SsiException>().having((e) => e.message, 'message',
              contains('first element of @context must be a string URI'))));
    });

    test('Passing top-level map throws exception', () {
      expect(
          () => JsonLdContext.fromJson({'@vocab': 'https://schema.org/'}),
          throwsA(isA<SsiException>().having((e) => e.message, 'message',
              contains('Top-level @context must be a string URI or a list'))));
    });
  });

  group('MutableJsonLdContext', () {
    test('Mutable context from list', () {
      final context = MutableJsonLdContext.fromJson([
        'https://example.com/context',
        {'@vocab': 'https://schema.org/'}
      ]);
      expect(context.firstUri.toString(), 'https://example.com/context');

      (context.context as List)[1] = {
        '@vocab': 'https://schema.org/',
        'age': 'schema:age'
      };
      expect((context.context as List)[1],
          {'@vocab': 'https://schema.org/', 'age': 'schema:age'});
    });

    test('Single string mutable context as list', () {
      final context =
          MutableJsonLdContext.fromJson(['https://example.com/context']);
      expect(context.firstUri.toString(), 'https://example.com/context');

      context.context = ['https://example.org/new'];
      expect(context.firstUri.toString(), 'https://example.org/new');
      expect(context.toJson(), ['https://example.org/new']);
    });

    test('List with first element as map throws exception', () {
      expect(
          () => MutableJsonLdContext.fromJson([
                {'@vocab': 'https://schema.org/'},
                'https://example.com/context'
              ]),
          throwsA(isA<SsiException>().having((e) => e.message, 'message',
              contains('first element of @context must be a string URI'))));
    });

    test('Passing top-level map throws exception', () {
      expect(
          () =>
              MutableJsonLdContext.fromJson({'@vocab': 'https://schema.org/'}),
          throwsA(isA<SsiException>().having((e) => e.message, 'message',
              contains('Top-level @context must be a string URI or a list'))));
    });
  });
  group('Complex Context Example', () {
    final seed = hexDecode(
      'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
    );

    test('Context1', () async {
      final signer = await initSigner(seed);
      final credential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson(context1),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        issuer: Issuer.uri(signer.did),
        holder: MutableHolder.uri('did:example:1'),
        issuanceDate: DateTime.now().toUtc(),
        credentialSubject: [
          MutableCredentialSubject({
            'data': {
              '@type': ['Person', 'PersonE', 'NamePerson'],
              'givenName': 'DenisUpdated',
              'familyName': 'Popov',
            },
          }),
        ],
        credentialSchema: [
          MutableCredentialSchema(
            id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
            type: 'JsonSchemaValidator2018',
          ),
        ],
      );

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(credential),
        proofGenerator: proofGenerator,
      );

      final json = jsonEncode(issuedCredential.toJson());

      final verifiableCredential = UniversalParser.parse(json.toString());

      final verifier = VcIntegrityVerifier();
      final result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
      expect(result.errors.length, 0);
      expect(result.warnings.length, 0);
    });

    test('Context2', () async {
      final signer = await initSigner(seed);
      final credential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson(context1),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        issuer: Issuer.uri(signer.did),
        holder: MutableHolder.uri('did:example:1'),
        issuanceDate: DateTime.now().toUtc(),
        credentialSubject: [
          MutableCredentialSubject({
            'data': {
              '@type': ['Person', 'PersonE', 'NamePerson'],
              'givenName': 'DenisUpdated',
              'familyName': 'Popov',
            },
          }),
        ],
        credentialSchema: [
          MutableCredentialSchema(
            id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
            type: 'JsonSchemaValidator2018',
          ),
        ],
      );

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(credential),
        proofGenerator: proofGenerator,
      );

      final json = jsonEncode(issuedCredential.toJson());

      final verifiableCredential = UniversalParser.parse(json.toString());

      final verifier = VcIntegrityVerifier();
      final result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
      expect(result.errors.length, 0);
      expect(result.warnings.length, 0);
    });

    test('Context3', () async {
      final signer = await initSigner(seed);
      final credential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson(context1),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        issuer: Issuer.uri(signer.did),
        holder: MutableHolder.uri('did:example:1'),
        issuanceDate: DateTime.now().toUtc(),
        credentialSubject: [
          MutableCredentialSubject({
            'data': {
              '@type': ['Person', 'PersonE', 'NamePerson'],
              'givenName': 'DenisUpdated',
              'familyName': 'Popov',
            },
          }),
        ],
        credentialSchema: [
          MutableCredentialSchema(
            id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
            type: 'JsonSchemaValidator2018',
          ),
        ],
      );

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(credential),
        proofGenerator: proofGenerator,
      );

      final json = jsonEncode(issuedCredential.toJson());

      final verifiableCredential = UniversalParser.parse(json.toString());

      final verifier = VcIntegrityVerifier();
      final result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
      expect(result.errors.length, 0);
      expect(result.warnings.length, 0);
    });

    test('Context4 invalid', () async {
      final signer = await initSigner(seed);

      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/ns/credentials/v2',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        issuer: Issuer.uri(signer.did),
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Fname',
            'Lname': 'Lame',
            'Age': '22',
            'Address': 'Eihhornstr'
          }),
        ],
        credentialSchema: [
          MutableCredentialSchema(
            id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
            type: 'JsonSchemaValidator2018',
          ),
        ],
      );

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issuedCredential = await LdVcDm2Suite().issue(
        unsignedData: VcDataModelV2.fromMutable(credential),
        proofGenerator: proofGenerator,
      );

      final json = jsonEncode(issuedCredential.toJson());

      final ldV2VC = UniversalParser.parse(json.toString());

      final v2Vp = MutableVpDataModelV2(
        context: MutableJsonLdContext.fromJson(
            'https://www.w3.org/ns/credentials/v2'),
        id: Uri.parse('testVpV1Id'),
        type: {'VerifiablePresentation'},
        holder: MutableHolder.uri(signer.did),
        verifiableCredential: [ldV2VC],
      );

      final vpProofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );

      final vpToSign = VpDataModelV2.fromMutable(v2Vp);
      final issuedVp = await LdVpDm2Suite()
          .issue(unsignedData: vpToSign, proofGenerator: vpProofGenerator);

      final issuedVpString = issuedVp.serialized;
      final verificationStatus = await VpIntegrityVerifier()
          .verify(UniversalPresentationParser.parse(issuedVpString));

      expect(verificationStatus.isValid, true);
      expect(verificationStatus.errors.length, 0);
      expect(verificationStatus.warnings.length, 0);
    });
  });
}
