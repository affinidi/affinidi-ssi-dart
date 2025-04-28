import 'dart:typed_data';

import 'package:ssi/src/credentials/presentations/linked_data/ld_vp_dm_v2_suite.dart';
import 'package:ssi/src/credentials/presentations/models/v2/vp_data_model_v2.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_proof_expiry_verifier.dart';
import 'package:ssi/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../../test_utils.dart';

void main() async {
  final testSeed = Uint8List.fromList(List.generate(32, (index) => index + 1));

  final ldV2VC = UniversalParser.parse(VerifiableCredentialDataFixtures
      .credentialWithValidProofDataModelV20String);

  final signer = await initSigner(testSeed);

  group('VP LD V2 Proof Expiry Verification', () {
    test('should be able to verify expiry of VP proof', () async {
      final v2Vp = MutableVpDataModelV2(
          context: [MutableVpDataModelV2.contextUrl],
          id: 'testVpV2',
          type: ['VerifiablePresentation'],
          verifiableCredential: [ldV2VC]);

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      var issuedCredential = await LdVpDm2Suite().issue(
          unsignedData: v2Vp,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus =
          await VpProofExpiryVerifier(getNow: getNow).verify(issuedCredential);
      expect(verificationStatus.isValid, true);
      expect(verificationStatus.errors, []);
    });

    test('should be able to verify for expired  VP proof', () async {
      final v2Vp = MutableVpDataModelV2(
          context: [MutableVpDataModelV2.contextUrl],
          id: 'testVpV2',
          type: ['VerifiablePresentation'],
          verifiableCredential: [ldV2VC]);
      final proofGenerator =
          Secp256k1Signature2019Generator(signer: signer, expires: getPast());
      var issuedCredential = await LdVpDm2Suite().issue(
          unsignedData: v2Vp,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus =
          await VpProofExpiryVerifier().verify(issuedCredential);
      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors, ['proof is no longer valid']);
    });

    test('should be able to verify for future expiry of  VP proof', () async {
      final v2Vp = MutableVpDataModelV2(
          context: [MutableVpDataModelV2.contextUrl],
          id: 'testVpV2',
          type: ['VerifiablePresentation'],
          verifiableCredential: [ldV2VC]);
      final proofGenerator =
          Secp256k1Signature2019Generator(signer: signer, expires: getFuture());
      var issuedCredential = await LdVpDm2Suite().issue(
          unsignedData: v2Vp,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus =
          await VpProofExpiryVerifier(getNow: getPast).verify(issuedCredential);
      expect(verificationStatus.isValid, true);
      expect(verificationStatus.errors, []);
    });
  });
}
