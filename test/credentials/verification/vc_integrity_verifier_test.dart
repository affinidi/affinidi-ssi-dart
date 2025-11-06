import 'dart:convert';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('VC Integrity Verifier', () {
    test('Should pass for valid VC issues by other libs', () async {
      final vcList = [
        VerifiableCredentialDataFixtures
            .credentialWithEcdsaSecp256k1Signature2019ByVault,
        VerifiableCredentialDataFixtures
            .credentialWithEcdsaRdfc2019ByDigitalBazaar,
        VerifiableCredentialDataFixtures
            .credentialWithEddsaRdfc2022ByDigitalBazaar
      ];

      for (final vc in vcList) {
        final verifiableCredential = UniversalParser.parse(vc);

        final verifier = VcIntegrityVerifier();
        var result = await verifier.verify(verifiableCredential);

        expect(result.isValid, true);
        expect(result.errors, <String>[]);
        expect(result.warnings, <String>[]);
      }
    });

    test('Should pass for valid VC from CWE', () async {
      var data = VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe;
      final verifiableCredential = UniversalParser.parse(data);

      final verifier = VcIntegrityVerifier();
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
      expect(result.errors, <String>[]);
      expect(result.warnings, <String>[]);
    });

    test('Should failed verification for jwt dm v1 for invalid signature',
        () async {
      final verifier = VcIntegrityVerifier();
      var data =
          VerifiableCredentialDataFixtures.jwtCredentialDataModelV11InvalidSig;
      final verifiableCredential = UniversalParser.parse(data);
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, false);
      expect(
          result.errors, [SsiExceptionType.failedIntegrityVerification.code]);
      expect(result.warnings, <String>[]);
    });

    test('Should pass verification for sdjwt', () async {
      final verifier = VcIntegrityVerifier();
      var data = VerifiableCredentialDataFixtures.sdJwtWithValidSig;
      final verifiableCredential = UniversalParser.parse(data);
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
    });

    test('Should pass for a VC with single proof in object format', () async {
      final data = VerifiableCredentialDataFixtures
          .credentialWithValidProofDataModelV11JsonEncoded;

      final verifiableCredential = UniversalParser.parse(data);

      final verifier = VcIntegrityVerifier();
      var result = await verifier.verify(verifiableCredential);

      // This should work since it's a valid signature, just in array format
      expect(result.isValid, true);
      expect(result.errors.isEmpty, true);
    });

    test('Should pass for a VC with single proof in array format', () async {
      final originalVc =
          VerifiableCredentialDataFixtures.credentialWithValidProofDataModelV11;

      // Convert single proof object to array format
      final originalProof = originalVc['proof'];
      originalVc['proof'] = [originalProof]; // Wrap in array

      final data = jsonEncode(originalVc);
      final verifiableCredential = UniversalParser.parse(data);

      final verifier = VcIntegrityVerifier();
      var result = await verifier.verify(verifiableCredential);

      // This should work since it's a valid signature, just in array format
      expect(result.isValid, true);
      expect(result.errors.isEmpty, true);
    });

    test('Should fail verification when proof array is empty', () async {
      // Take an existing working VC and modify it to have empty proof array
      final originalVc = jsonDecode(VerifiableCredentialDataFixtures
          .credentialWithValidProofDataModelV11JsonEncoded);

      // Remove the proof to make it empty array
      originalVc['proof'] = <dynamic>[]; // Empty proof array
      final vcWithEmptyProofArray = jsonEncode(originalVc);
      final verifiableCredential = UniversalParser.parse(vcWithEmptyProofArray);

      final verifier = VcIntegrityVerifier();
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, false);
      expect(result.errors.isNotEmpty, true);
    });

    test('Should fail when one of the proof is invalid', () async {
      final vcWithOneInvalidProof = VerifiableCredentialDataFixtures
          .credentialWithOneInvalidProofInProofSet;

      final verifiableCredential = UniversalParser.parse(vcWithOneInvalidProof);

      final verifier = VcIntegrityVerifier();
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, false);
      expect(
          result.errors, [SsiExceptionType.failedIntegrityVerification.code]);
    });

    test('Should pass when all the proofs are valid ', () async {
      final vcWithAllValidProofs =
          VerifiableCredentialDataFixtures.credentialWithValidProofSet;

      final verifiableCredential = UniversalParser.parse(vcWithAllValidProofs);

      final verifier = VcIntegrityVerifier();
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
      expect(result.errors.isEmpty, true);
    });
  });
}
