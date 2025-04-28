import 'dart:typed_data';

import 'package:ssi/src/credentials/presentations/linked_data/ld_vp_dm_v1_suite.dart';
import 'package:ssi/src/credentials/presentations/models/v1/vp_data_model_v1.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_domain_challenge_verifier.dart';
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

  group('VP LD V1 Domain Challenge Verification', () {
    test('should be able to verify domain and challenge of VP proof', () async {
      final v1Vp = MutableVpDataModelV1(
          context: [MutableVpDataModelV1.contextUrl],
          id: 'testVpV1',
          type: ['VerifiablePresentation'],
          verifiableCredential: [ldV1VC]);

      final proofGenerator = Secp256k1Signature2019Generator(
          signer: signer, domain: ['fun.com'], challenge: 'test-challenge');
      var issuedCredential = await LdVpDm1Suite().issue(
          unsignedData: v1Vp,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus = await VpDomainChallengeVerifier(
              domain: ['fun.com'], challenge: 'test-challenge')
          .verify(issuedCredential);
      expect(verificationStatus.isValid, true);
      expect(verificationStatus.errors, []);
    });

    test('should fail for invalid provided domain', () async {
      final v1Vp = MutableVpDataModelV1(
          context: [MutableVpDataModelV1.contextUrl],
          id: 'testVpV1',
          type: ['VerifiablePresentation'],
          verifiableCredential: [ldV1VC]);

      final proofGenerator = Secp256k1Signature2019Generator(
          signer: signer, domain: ['fun.com'], challenge: 'test-challenge');
      var issuedCredential = await LdVpDm1Suite().issue(
          unsignedData: v1Vp,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus = await VpDomainChallengeVerifier(
              domain: ['NotVerify.com'], challenge: 'test-challenge')
          .verify(issuedCredential);
      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors, ['invalid or missing proof.domain']);
    });

    test('should fail for invalid provided challenge', () async {
      final v1Vp = MutableVpDataModelV1(
          context: [MutableVpDataModelV1.contextUrl],
          id: 'testVpV1',
          type: ['VerifiablePresentation'],
          verifiableCredential: [ldV1VC]);

      final proofGenerator = Secp256k1Signature2019Generator(
          signer: signer, domain: ['fun.com'], challenge: 'test-challenge');
      var issuedCredential = await LdVpDm1Suite().issue(
          unsignedData: v1Vp,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final verificationStatus = await VpDomainChallengeVerifier(
              domain: ['fun.com'], challenge: 'wrong challenge')
          .verify(issuedCredential);
      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors, ['invalid or missing proof.challenge']);
    });
  });
}
