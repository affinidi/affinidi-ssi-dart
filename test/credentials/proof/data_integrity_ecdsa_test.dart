import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final signer = await initP256Signer(seed);
  // TODO: Add P384 signer when available in test utils
  // final p384Signer = await initP384Signer(seed);
  final edSigner = await initEdSigner(seed);

  group('Test Data Integrity ECDSA VC issuance', () {
    final multiBaseList = [MultiBase.base58bitcoin, MultiBase.base64UrlNoPad];

    for (final proofValueMultiBase in multiBaseList) {
      group(proofValueMultiBase.name, () {
        test('Create and verify Data Integrity ECDSA proof', () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: [
              'https://www.w3.org/2018/credentials/v1',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ],
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
            issuer: Issuer.uri(signer.did),
          );

          final proofGenerator = DataIntegrityEcdsaGenerator(
            signer: signer,
            proofValueMultiBase: proofValueMultiBase,
          );

          final issuedCredential = await LdVcDm1Suite().issue(
            unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
            proofGenerator: proofGenerator,
          );

          final proofVerifier =
              DataIntegrityEcdsaVerifier(issuerDid: signer.did);

          final verificationResult =
              await proofVerifier.verify(issuedCredential.toJson());

          expect(verificationResult.isValid, true);
          expect(verificationResult.errors, isEmpty);
          expect(verificationResult.warnings, isEmpty);

          final proof =
              issuedCredential.toJson()['proof'] as Map<String, dynamic>;
          expect(proof['type'], 'DataIntegrityProof');
          expect(proof['cryptosuite'], 'ecdsa-rdfc-2019');
          expect(proof['proofValue'], isNotNull);

          final proofValueHeader = proof['proofValue'][0];
          expect(proofValueHeader,
              proofValueMultiBase == MultiBase.base58bitcoin ? 'z' : 'u');
        });

        test('Verify Data Integrity ECDSA proof through LdBaseSuite', () async {
          final unsignedCredential = MutableVcDataModelV1(
            context: [
              'https://www.w3.org/2018/credentials/v1',
              'https://schema.affinidi.com/UserProfileV1-0.jsonld'
            ],
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
            issuer: Issuer.uri(signer.did),
          );

          final proofGenerator = DataIntegrityEcdsaGenerator(
            signer: signer,
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

  group('Test Data Integrity ECDSA-JCS VC issuance', () {
    test('Create and verify Data Integrity ECDSA-JCS proof with P-256',
        () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: [
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ],
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
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final proofVerifier =
          DataIntegrityEcdsaJcsVerifier(issuerDid: signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);

      final proof = issuedCredential.toJson()['proof'] as Map<String, dynamic>;
      expect(proof['type'], 'DataIntegrityProof');
      expect(proof['cryptosuite'], 'ecdsa-jcs-2019');
      expect(proof['proofValue'], isNotNull);
      expect(proof['proofValue'], startsWith('z')); // base58-btc multibase
    });

    // TODO: Re-enable when P384 signer is available in test utils
    /*test('Create and verify Data Integrity ECDSA-JCS proof with P-384', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: [
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ],
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
        issuer: Issuer.uri(p384Signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: p384Signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final proofVerifier = DataIntegrityEcdsaJcsVerifier(issuerDid: p384Signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);

      final proof = issuedCredential.toJson()['proof'] as Map<String, dynamic>;
      expect(proof['type'], 'DataIntegrityProof');
      expect(proof['cryptosuite'], 'ecdsa-jcs-2019');
      expect(proof['proofValue'], isNotNull);
      expect(proof['proofValue'], startsWith('z')); // base58-btc multibase
    });*/

    test('JCS context validation works correctly', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: [
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ],
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({'name': 'Test User'})
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      // Verify that the proof contains the same @context as the document
      final credentialJson = issuedCredential.toJson();
      final proof = credentialJson['proof'] as Map<String, dynamic>;

      // The proof should NOT have @context in the final form (it's removed after signing)
      expect(proof.containsKey('@context'), false);

      final proofVerifier =
          DataIntegrityEcdsaJcsVerifier(issuerDid: signer.did);
      final verificationResult = await proofVerifier.verify(credentialJson);

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
    });

    test('ECDSA-JCS rejects unsupported signature schemes', () {
      expect(
        () => DataIntegrityEcdsaJcsGenerator(signer: edSigner),
        throwsA(isA<SsiException>()),
      );
    });

    test('Verify Data Integrity ECDSA-JCS proof through LdBaseSuite', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: [
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ],
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
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaJcsGenerator(
        signer: signer,
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
