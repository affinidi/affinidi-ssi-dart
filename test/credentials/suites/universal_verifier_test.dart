import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';

void main() {
  final validCredential = UniversalParser.parse(
    VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe,
  );

  group('UniversalVerifier', () {
    test('should pass verification for ld dm v1', () async {
      final verifier = UniversalVerifier();

      var result = await verifier.verify(validCredential);

      expect(result.isValid, true);
    });

    test('should execute custom verifiers and pass', () async {
      final verifier = UniversalVerifier(
        customVerifiers: [
          _TestVerifier(VerificationResult.ok()),
        ],
      );

      var result = await verifier.verify(validCredential);

      expect(result.isValid, true);
    });

    test('should execute custom verifiers and collect issues', () async {
      final verifier = UniversalVerifier(
        customVerifiers: [
          _TestVerifier(
            VerificationResult.ok(warnings: ['warning1']),
          ),
          _TestVerifier(
            VerificationResult.invalid(errors: ['error1']),
          ),
          _TestVerifier(
            VerificationResult.invalid(errors: ['error2', 'error3']),
          ),
        ],
      );

      var result = await verifier.verify(validCredential);

      expect(result.isValid, false);
      expect(result.warnings, ['warning1']);
      expect(result.errors, ['error1', 'error2', 'error3']);
    });
  });
}

class _TestVerifier implements VcVerifier {
  final VerificationResult result;

  _TestVerifier(this.result);

  @override
  Future<VerificationResult> verify(ParsedVerifiableCredential vc) {
    return Future.value(result);
  }
}
