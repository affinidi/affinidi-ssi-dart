// ignore_for_file: avoid_print

import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_integrity_verifier.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  group('VP LD V2 Integrity Verification', () {
    test('should be able to verify the integrity of a valid V2 presentation',
        () async {
      final v2Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v2VpString);
      final verificationStatus = await VpIntegrityVerifier().verify(v2Vp);

      expect(verificationStatus.errors.length, 0);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, true);
    });

    test('should be able to verify the integrity of an invalid V2 presentation',
        () async {
      final v2Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.invalidV2VpString);
      final verificationStatus = await VpIntegrityVerifier().verify(v2Vp);

      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
    });

    test(
        'should be able to verify the integrity of a valid V2 presentation containing invalid VC',
        () async {
      final v2Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v2VpWithInvalidVCString);

      final verificationStatus = await VpIntegrityVerifier().verify(v2Vp);

      expect(verificationStatus.isValid, false);
      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
    });
  });
}
