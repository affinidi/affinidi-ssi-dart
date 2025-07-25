import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/did/public_key_utils.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final edSigner = await initEdSigner(seed);

  group('Test Data Integrity EdDSA VC issuance', () {
    final multiBaseList = [MultiBase.base58bitcoin, MultiBase.base64UrlNoPad];

    for (final proofValueMultiBase in multiBaseList) {
      group(proofValueMultiBase.name, () {
        test('Create and verify Data Integrity EdDSA proof', () async {
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
            issuer: Issuer.uri(edSigner.did),
          );

          final proofGenerator = DataIntegrityEddsaGenerator(
            signer: edSigner,
            proofValueMultiBase: proofValueMultiBase,
          );

          final issuedCredential = await LdVcDm1Suite().issue(
            unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
            proofGenerator: proofGenerator,
          );

          final proofVerifier =
              DataIntegrityEddsaVerifier(issuerDid: edSigner.did);

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

        test('Verify Data Integrity EdDSA proof through LdBaseSuite', () async {
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
            issuer: Issuer.uri(edSigner.did),
          );

          final proofGenerator = DataIntegrityEddsaGenerator(
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
}
