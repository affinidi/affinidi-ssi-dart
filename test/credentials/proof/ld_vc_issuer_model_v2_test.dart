import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/linked_data/ld_dm_v2_suite.dart';
import 'package:ssi/src/credentials/models/field_types/credential_subject.dart';
import 'package:ssi/src/credentials/models/field_types/issuer.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart';
import 'package:ssi/src/credentials/suites/universal_verifier.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../test_utils.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  group('Test Linked Data VC DM2 issuance', () {
    test('Create and verify proof', () async {
      final signer = await initSigner(seed);

      final unsignedCredential = MutableVcDataModelV2(
        context: [
          DMV2ContextUrl,
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ],
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            "Fname": "Fname",
            "Lname": "Lame",
            "Age": "22",
            "Address": "Eihhornstr"
          })
        ],
        credentialSchema: [
          MutableCredentialSchema(
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        validFrom: DateTime.now(),
        validUntil: DateTime.now().add(const Duration(days: 365)),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );
      final issuedCredential = await LdVcDm2Suite().issue(
          unsignedData: VcDataModelV2.fromMutable(unsignedCredential),
          proofGenerator: proofGenerator);

      final verificationResult =
          await UniversalVerifier().verify(issuedCredential);

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('V2 fixture verify', () async {
      final unsigned = LdVcDm2Suite().parse(VerifiableCredentialDataFixtures
          .credentialWithValidProofDataModelV20String);
      // final issuedCredential = await LdVcDm1Suite().issue(unsigned, signer);

      final validationResult = await LdVcDm2Suite().verifyIntegrity(unsigned);

      expect(validationResult, true);
    });
  });
}
