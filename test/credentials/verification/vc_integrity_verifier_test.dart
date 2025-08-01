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
  });
}
