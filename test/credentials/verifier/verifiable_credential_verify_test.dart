import 'package:ssi/src/credentials/factories/verifiable_credential_verify.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('CredentialVerifier', () {
    test('should call appropriate verifier', () async {
      final verifier = CredentialVerifier();
      final verifiableCredential = VerifiableCredentialParser.parse(
        VerifiableCredentialDataFixtures
            .credentialWithProofDataModelV11JsonEncoded,
      );
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, false);
      expect(result.errors, []);
    });
  });
}
