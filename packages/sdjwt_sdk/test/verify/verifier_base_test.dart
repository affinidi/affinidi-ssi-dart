import 'package:sdjwt_sdk/src/verify/jwt_verifier_base.dart';
import 'package:test/test.dart';

class TestJwtVerifier with JwtVerifier {}

void main() {
  group('JwtVerifier', () {
    late TestJwtVerifier verifier;

    setUp(() {
      verifier = TestJwtVerifier();
    });

    group('verifyTimeBasedClaims', () {
      test('should return true for valid time-based claims', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final payload = {
          'exp': now + 3600,
          'iat': now - 3600,
          'nbf': now - 1800,
        };

        expect(verifier.verifyTimeBasedClaims(payload), isTrue);
      });

      test('should return false for expired token', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final payload = {
          'exp': now - 3600,
          'iat': now - 7200,
        };

        expect(verifier.verifyTimeBasedClaims(payload), isFalse);
      });

      test('should return false for future issued token', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final payload = {
          'exp': now + 7200,
          'iat': now + 3600,
        };

        expect(verifier.verifyTimeBasedClaims(payload), isFalse);
      });

      test('should return false for not-yet-valid token', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final payload = {
          'exp': now + 7200,
          'iat': now - 3600,
          'nbf': now + 1800,
        };

        expect(verifier.verifyTimeBasedClaims(payload), isFalse);
      });

      test('should throw for missing exp claim', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final payload = {
          'iat': now - 3600,
        };

        expect(() => verifier.verifyTimeBasedClaims(payload), throwsException);
      });

      test('should throw for missing iat claim', () {
        final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
        final payload = {
          'exp': now + 3600,
        };

        expect(() => verifier.verifyTimeBasedClaims(payload), throwsException);
      });
    });
  });
}
