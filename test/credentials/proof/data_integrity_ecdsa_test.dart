import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final signer = await initP256Signer(seed);

  group('Test Data Integrity ECDSA VC issuance', () {
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
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaGenerator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final proofVerifier = DataIntegrityEcdsaVerifier(issuerDid: signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);

      final proof = issuedCredential.toJson()['proof'] as Map<String, dynamic>;
      expect(proof['type'], 'DataIntegrityProof');
      expect(proof['cryptosuite'], 'ecdsa-rdfc-2019');
      expect(proof['proofValue'], isNotNull);
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
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = DataIntegrityEcdsaGenerator(
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
