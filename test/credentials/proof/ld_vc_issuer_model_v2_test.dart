import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/linked_data/ld_dm_v2_suite.dart';
import 'package:ssi/src/credentials/models/credential_subject.dart';
import 'package:ssi/src/credentials/models/issuer.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
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
          MutableVcDataModelV2.contextUrl,
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ],
        id: 'uuid:123456abcd',
        type: ['VerifiableCredential', 'UserProfile'],
        credentialSubject: CredentialSubject(claims: {
          "Fname": "Fname",
          "Lname": "Lame",
          "Age": "22",
          "Address": "Eihhornstr"
        }),
        credentialSchema: [
          CredentialSchema.fromJson({
            'id': 'https://schema.affinidi.com/UserProfileV1-0.json',
            'type': 'JsonSchemaValidator2018'
          })
        ],
        validFrom: DateTime.now(),
        validUntil: DateTime.now().add(const Duration(days: 365)),
        issuer: Issuer(id: signer.did),
      );

      final issuedCredential =
          await LdVcDm2Suite().issue(unsignedCredential, signer);

      final verificationResult =
          await UniversalVerifier().verify(issuedCredential);

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('V2 fixture verify', () async {
      final unsigned = LdVcDm2Suite().parse(VerifiableCredentialDataFixtures
          .credentialWithProofDataModelV20String);
      // final issuedCredential = await LdVcDm1Suite().issue(unsigned, signer);

      final validationResult = await LdVcDm2Suite().verifyIntegrity(unsigned);

      expect(validationResult, true);
    });
  });
}
