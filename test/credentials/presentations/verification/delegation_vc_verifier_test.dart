import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/presentations/verification/delegation_vc_verifier.dart';
import 'package:test/test.dart';
import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() {
  group('DelegationVcVerifier', () {
    test('should pass if all holders at VCs are VP signer', () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithFullDelegationVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test('should pass if there is DelegationVC and all matches', () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithDelegationVCString);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test('should pass if restricted delegationLevel with all VCs matching',
        () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithRestrictedDelegationVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test('should pass if delegationLevel "full", all VCs allowed', () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithFullDelegationVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test('should fail if the signer of DelegationVC is not a VP holder',
        () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithInvalidDelegationHolder);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors,
          contains('Invalid delegation VC holder: did:key:anotherholder'));
    });
    test('should fail if there are missing vcIds at the DelegationVC',
        () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithMissingVcId);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors, contains('Missing delegation VC IDs: claimid:vc2'));
    });

    test('should fail if delegationLevel is "restricted" and unexpected VCs id',
        () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithUnexpectedDelegatedVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors,
          contains('Unexpected VCs in the Delegation VC: claimid:unexpected'));
    });

    test('should fail if invalid delegationLevel provided', () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithInvalidDelegationLevel);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors, contains('Invalid delegation level: wrong-level'));
    });

    test(
        'should verify VP with delegation from DID1 and DID2 to DID3 (restricted)',
        () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithMultiDelegationRestricted);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test(
        'should verify VP with delegation from DID1 and DID2 to DID3 (restricted and full)',
        () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithMultiDelegationMixed);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test('should verify VP with delegation from DID1 and DID2 to DID3 (full)',
        () async {
      final verifier = DelegationVcVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithMultiDelegationMixed);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });
  });

  test('should pass if V2 VC has no holder and uses credentialSubject.id',
      () async {
    final verifier = DelegationVcVerifier();
    final vp = UniversalPresentationParser.parse(
        VerifiablePresentationDataFixtures.v2VpWithMissingHolder);
    final result = await verifier.verify(vp);
    expect(result.isValid, true);
    expect(result.errors, isEmpty);
    expect(result.warnings, isEmpty);
  });
}
