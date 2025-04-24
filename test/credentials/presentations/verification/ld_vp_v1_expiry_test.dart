import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_expiry_verifier.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  final v1Vp = UniversalPresentationParser.parse(
      VerifiablePresentationDataFixtures.v1VpWithExpiringVCString);

  group('VP LD V1 Expiry Verification', () {
    test(
        'should be able to verify the time validity of VCs embedded within a V1 presentation',
        () async {
      final verificationStatus =
          await VpExpiryVerifier(getNow: _getNow).verify(v1Vp);
      expect(verificationStatus.errors.length, 0);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, true);
    });

    test(
        'should be able to verify the time validity of an expired VC embedded within a V1 presentation',
        () async {
      final verificationStatus =
          await VpExpiryVerifier(getNow: _getFuture).verify(v1Vp);

      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
    });

    test(
        'should be able to verify the time validity of a future valid VC embedded within a V1 presentation',
        () async {
      final verificationStatus =
          await VpExpiryVerifier(getNow: _getPast).verify(v1Vp);

      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
    });
  });
}

DateTime _getNow() {
  return DateTime.parse('2025-04-25');
}

DateTime _getPast() {
  return _getNow().subtract(const Duration(days: 400));
}

DateTime _getFuture() {
  return _getNow().add(const Duration(days: 400));
}
