import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_integrity_verifier.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  group('VP LD V1 Integrity Verification', () {
    test('should be able to verify the integrity of a valid V1 presentation',
        () async {
      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpString);
      final verificationStatus = await VpIntegrityVerifier().verify(v1Vp);
      expect(verificationStatus.errors.length, 0);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, true);
    });

    test('should be able to verify the integrity of an invalid V1 presentation',
        () async {
      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.invalidV1VpString);
      final verificationStatus = await VpIntegrityVerifier().verify(v1Vp);

      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
    });

    test(
        'should be able to verify the integrity of a valid V1 presentation containing invalid VC',
        () async {
      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithInvalidVCString);

      final verificationStatus = await VpIntegrityVerifier().verify(v1Vp);

      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
    });
  });
}
