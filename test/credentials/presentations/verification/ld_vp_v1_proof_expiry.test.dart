import 'dart:typed_data';

import 'package:ssi/src/credentials/models/field_types/holder.dart';
import 'package:ssi/src/credentials/presentations/linked_data/ld_vp_dm_v1_suite.dart';
import 'package:ssi/src/credentials/presentations/models/v1/vp_data_model_v1.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_proof_expiry_verifier.dart';
import 'package:ssi/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart';
import 'package:ssi/src/credentials/suites/universal_parser.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../../test_utils.dart';

void main() async {
  final testSeed = Uint8List.fromList(List.generate(32, (index) => index + 1));

  final ldV1VC = UniversalParser.parse(VerifiableCredentialDataFixtures
      .credentialWithValidProofDataModelV11JsonEncoded);
  final signer = await initSigner(testSeed);

  group('VP LD V1 Proof Expiry Verification', () {
    final v1Vp = MutableVpDataModelV1(
          context: [VpDataModelV1.contextUrl],
          id: Uri.parse('testVpV1'),
          type: {'VerifiablePresentation'},
          holder: Holder.uri(signer.did),
          verifiableCredential: [ldV1VC]);
    test('should be able to verify expiry of VP proof', () async {
      

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      var issuedCredential = await LdVpDm1Suite().issue(
          unsignedData: VpDataModelV1.fromJson(v1Vp.toJson()),
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus =
          await VpProofExpiryVerifier(getNow: getNow).verify(issuedCredential);
      expect(verificationStatus.isValid, true);
      expect(verificationStatus.errors, []);
    });

    test('should be able to verify for expired  VP proof', () async {


      final proofGenerator =
          Secp256k1Signature2019Generator(signer: signer, expires: getPast());
      var issuedCredential = await LdVpDm1Suite().issue(
          unsignedData: VpDataModelV1.fromJson(v1Vp.toJson()),
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus =
          await VpProofExpiryVerifier().verify(issuedCredential);
      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors, ['proof is no longer valid']);
    });

    test('should be able to verify for future expiry of  VP proof', () async {


      final proofGenerator =
          Secp256k1Signature2019Generator(signer: signer, expires: getFuture());
      var issuedCredential = await LdVpDm1Suite().issue(
          unsignedData: VpDataModelV1.fromJson(v1Vp.toJson()),
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus =
          await VpProofExpiryVerifier(getNow: getPast).verify(issuedCredential);
      expect(verificationStatus.isValid, true);
      expect(verificationStatus.errors, []);
    });
  });
}
