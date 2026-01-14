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

    test('should use custom document loader', () async {
      // Create a mock document loader that records the URLs it's called with
      final loadedUrls = <Uri>[];
      Future<Map<String, dynamic>?> customDocumentLoader(Uri url) async {
        loadedUrls.add(url);
        // Return a basic JSON-LD context
        return {
          '@context': {
            '@version': 1.1,
            'id': '@id',
            'type': '@type',
          }
        };
      }

      // Create a verifier with the custom document loader
      final verifier = UniversalVerifier(
        customDocumentLoader: customDocumentLoader,
      );

      // Print the credential type to help debug

      // Verify a credential
      var result = await verifier.verify(validCredential);

      // Verify that the document loader was called
      expect(loadedUrls.isNotEmpty, true,
          reason: 'Custom document loader was not called');

      // The verification fails with integrity_verification_failed because our simple
      // document loader doesn't provide all the necessary context information.
      // This is expected and doesn't indicate a problem with the document loader functionality.
      expect(result.errors[0], contains('integrity_verification_failed'));
    });

    test('should use cached verifiers', () async {
      // Create a verifier with cached verifiers
      final verifier = UniversalVerifier.createWithCachedVerifiers();

      // Verify a credential
      var result = await verifier.verify(validCredential);

      // Verify that the verification was successful
      expect(result.isValid, true);
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
