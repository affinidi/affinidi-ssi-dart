import 'package:ssi/src/credentials/linked_data/ld_vc_data_model_v1.dart';
import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/verification/vp_integrity_verifier.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  final v2Vp = UniversalPresentationParser.parse(
      VerifiablePresentationDataFixtures.v2VpString);

  group('VP LD V1 Integrity Verification', () {
    test('should be able to verify the integrity of a valid V1 presentation',
        () async {
      final verificationStatus = await VpIntegrityVerifier().verify(v2Vp);
      expect(verificationStatus.errors.length, 0);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, true);
    });

    test('should be able to verify the integrity of an invalid V1 presentation',
        () async {
      v2Vp.proof['proofValue'] = '${v2Vp.proof['proofValue']}invalid';
      final verificationStatus = await VpIntegrityVerifier().verify(v2Vp);
      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, false);
    });

    test(
        'should be able to verify the integrity of a valid V1 presentation containing invalid VC',
        () async {
      final ldVCV1 = v2Vp.verifiableCredential[0] as LdVcDataModelV1;
      ldVCV1.proof['proofValue'] = '${ldVCV1.proof['proofValue']}invalid';

      final verificationStatus = await VpIntegrityVerifier().verify(v2Vp);
      expect(verificationStatus.errors.length, 1);
      expect(verificationStatus.warnings.length, 0);
      expect(verificationStatus.isValid, false);
    });
  });
}
