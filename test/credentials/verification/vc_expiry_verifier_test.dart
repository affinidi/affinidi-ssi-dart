import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  group('Test Expiry Verifier', () {
    test('Should be valid', () async {
      var data = VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe;
      final verifiableCredential = UniversalParser.parse(data);

      final verifier = VcExpiryVerifier(
        getNow: () => DateTime.parse('2023-01-01T09:51:00.273Z'),
      );
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, true);
      expect(result.errors, <String>[]);
      expect(result.warnings, <String>[]);
    });

    test('Should not yet be valid', () async {
      var data = VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe;
      final verifiableCredential = UniversalParser.parse(data);

      final verifier = VcExpiryVerifier(
        getNow: () => DateTime.parse('2023-01-01T09:51:00.271Z'),
      );
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, false);
      expect(result.errors,
          ['vc is not yet valid, validFrom: "2023-01-01 09:51:00.272Z"']);
      expect(result.warnings, <String>[]);
    });

    test('Should be expired', () async {
      var data = VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe;
      final verifiableCredential = UniversalParser.parse(data);

      final verifier = VcExpiryVerifier(
        getNow: () => DateTime.parse('3024-01-01T12:00:01Z'),
      );
      var result = await verifier.verify(verifiableCredential);

      expect(result.isValid, false);
      expect(result.errors,
          ['vc is no longer valid, validUntil: "3024-01-01 12:00:00.000Z"']);
      expect(result.warnings, <String>[]);
    });
  });
}
