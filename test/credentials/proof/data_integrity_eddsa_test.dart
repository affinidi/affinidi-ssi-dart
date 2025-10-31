import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final edSigner = await initEdSigner(seed);
  final p256Signer = await initP256Signer(seed);

  group('Test Data Integrity EdDSA-RDFC VC issuance', () {
    final multiBaseList = [MultiBase.base58bitcoin, MultiBase.base64UrlNoPad];

    for (final proofValueMultiBase in multiBaseList) {
      group(proofValueMultiBase.name, () {
        test('Create and verify Data Integrity EdDSA-RDFC proof', () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: MutableJsonLdContext.fromJson([
              'https://www.w3.org/2018/credentials/v1',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ]),
            id: Uri.parse('uuid:123456abcd'),
            type: {'VerifiableCredential', 'UserProfile'},
            credentialSubject: [
              MutableCredentialSubject({
                'Fname': 'Fname',
                'Lname': 'Lame',
                'Age': '22',
                'Address': 'Eihhornstr'
              })
            ],
            holder: MutableHolder.uri('did:example:1'),
            credentialSchema: [
              MutableCredentialSchema(
                  id: Uri.parse(
                      'https://schema.affinidi.com/UserProfileV1-0.json'),
                  type: 'JsonSchemaValidator2018')
            ],
            issuanceDate: DateTime.now(),
            issuer: Issuer.uri(edSigner.did),
          );

          final proofGenerator = DataIntegrityEddsaRdfcGenerator(
            signer: edSigner,
            proofValueMultiBase: proofValueMultiBase,
          );

          final issuedCredential = await LdVcDm1Suite().issue(
            unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
            proofGenerator: proofGenerator,
          );

          final proofVerifier =
              DataIntegrityEddsaRdfcVerifier(issuerDid: edSigner.did);

          final verificationResult =
              await proofVerifier.verify(issuedCredential.toJson());

          expect(verificationResult.isValid, true);
          expect(verificationResult.errors, isEmpty);
          expect(verificationResult.warnings, isEmpty);

          final proof =
              issuedCredential.toJson()['proof'] as Map<String, dynamic>;
          expect(proof['type'], 'DataIntegrityProof');
          expect(proof['cryptosuite'], 'eddsa-rdfc-2022');
          expect(proof['proofValue'], isNotNull);

          final proofValueHeader = proof['proofValue'][0];
          expect(proofValueHeader,
              proofValueMultiBase == MultiBase.base58bitcoin ? 'z' : 'u');
        });

        test('Verify Data Integrity EdDSA-RDFC proof through LdBaseSuite',
            () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: MutableJsonLdContext.fromJson([
              'https://www.w3.org/2018/credentials/v1',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ]),
            id: Uri.parse('uuid:123456abcd'),
            type: {'VerifiableCredential', 'UserProfile'},
            credentialSubject: [
              MutableCredentialSubject({
                'Fname': 'Fname',
                'Lname': 'Lame',
                'Age': '22',
                'Address': 'Eihhornstr'
              })
            ],
            holder: MutableHolder.uri('did:example:1'),
            credentialSchema: [
              MutableCredentialSchema(
                  id: Uri.parse(
                      'https://schema.affinidi.com/UserProfileV1-0.json'),
                  type: 'JsonSchemaValidator2018')
            ],
            issuanceDate: DateTime.now(),
            issuer: Issuer.uri(edSigner.did),
          );

          final proofGenerator = DataIntegrityEddsaRdfcGenerator(
            signer: edSigner,
            proofValueMultiBase: proofValueMultiBase,
          );

          final issuedCredential = await LdVcDm1Suite().issue(
            unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
            proofGenerator: proofGenerator,
          );

          final validationResult =
              await LdVcDm1Suite().verifyIntegrity(issuedCredential);

          final proof =
              issuedCredential.toJson()['proof'] as Map<String, dynamic>;
          final proofValueHeader = proof['proofValue'][0];

          expect(validationResult, true);
          expect(proofValueHeader,
              proofValueMultiBase == MultiBase.base58bitcoin ? 'z' : 'u');
        });
      });
    }
  });

  group('Test Data Integrity EdDSA-JCS VC issuance', () {
    test('Create and verify Data Integrity EdDSA-JCS proof', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Fname',
            'Lname': 'Lame',
            'Age': '22',
            'Address': 'Eihhornstr'
          })
        ],
        holder: MutableHolder.uri('did:example:1'),
        credentialSchema: [
          MutableCredentialSchema(
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(edSigner.did),
      );

      final proofGenerator = DataIntegrityEddsaJcsGenerator(
        signer: edSigner,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final proofVerifier =
          DataIntegrityEddsaJcsVerifier(verifierDid: edSigner.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);

      final proof = issuedCredential.toJson()['proof'] as Map<String, dynamic>;
      expect(proof['type'], 'DataIntegrityProof');
      expect(proof['cryptosuite'], 'eddsa-jcs-2022');
      expect(proof['proofValue'], isNotNull);
      expect(proof['proofValue'], startsWith('z')); // base58-btc multibase
    });

    test('JCS context validation works correctly', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({'name': 'Test User'})
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(edSigner.did),
      );

      final proofGenerator = DataIntegrityEddsaJcsGenerator(
        signer: edSigner,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      // Verify that the proof contains the same @context as the document
      final credentialJson = issuedCredential.toJson();
      final proof = credentialJson['proof'] as Map<String, dynamic>;

      expect(proof.containsKey('@context'), true);

      final proofVerifier =
          DataIntegrityEddsaJcsVerifier(verifierDid: edSigner.did);
      final verificationResult = await proofVerifier.verify(credentialJson);

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
    });

    test('EdDSA-JCS rejects unsupported signature schemes', () {
      expect(
        () => DataIntegrityEddsaJcsGenerator(signer: p256Signer),
        throwsA(isA<SsiException>()),
      );
    });

    test('Verify Data Integrity EdDSA-JCS proof through LdBaseSuite', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Fname',
            'Lname': 'Lame',
            'Age': '22',
            'Address': 'Eihhornstr'
          })
        ],
        holder: MutableHolder.uri('did:example:1'),
        credentialSchema: [
          MutableCredentialSchema(
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(edSigner.did),
      );

      final proofGenerator = DataIntegrityEddsaJcsGenerator(
        signer: edSigner,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final validationResult =
          await LdVcDm1Suite().verifyIntegrity(issuedCredential);

      expect(validationResult, true);
    });
  });
}
