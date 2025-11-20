import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() {
  group('NonceVerifier', () {
    test('should pass when no expected nonce is provided', () async {
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.vpWithNonce);
      final verifier = NonceVerifier();
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('should pass when no expected nonce and VP has no nonce', () async {
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.vpWithoutNonce);
      final verifier = NonceVerifier();
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('should fail when expected nonce does not exist in proof', () async {
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpString);
      final verifier = NonceVerifier(nonce: 'test-nonce');
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors, isNotEmpty);
      expect(result.errors.first,
          contains('Nonce is required but not found in proof'));
    });

    test('should fail when expected nonce does not match the nonce in proof',
        () async {
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.vpWithNonce);
      final verifier = NonceVerifier(nonce: 'invalid-test-nonce');
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors, isNotEmpty);
      expect(
          result.errors.first,
          contains(
              'Nonce mismatch: expected "invalid-test-nonce" but got "test-nonce"'));
    });
  });
}
