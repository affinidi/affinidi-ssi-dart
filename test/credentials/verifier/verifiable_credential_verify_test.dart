import 'package:ssi/src/credentials/factories/verifiable_credential_verify.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('CredentialVerifier', () {
    test('should pass verification for jwt dm v1', () async {
      final verifier = CredentialVerifier();
      var data = VerifiableCredentialDataFixtures.jwtCredentialDataModelV11;
      final verifiableCredential = VerifiableCredentialParser.parse(data);
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
    });

    test('should failed verification for jwt dm v1 for invalid signature',
        () async {
      final verifier = CredentialVerifier();
      var data =
          VerifiableCredentialDataFixtures.jwtCredentialDataModelV11InvalidSig;
      final verifiableCredential = VerifiableCredentialParser.parse(data);
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, false);
      expect(result.errors, ['integrity verification failed']);
    });

    test('should pass verification for ld dm v1', () async {
      final verifier = CredentialVerifier();
      var data = VerifiableCredentialDataFixtures
          .credentialWithValidProofDataModelV11JsonEncoded;
      final verifiableCredential = VerifiableCredentialParser.parse(data);
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
    });
  });
}
