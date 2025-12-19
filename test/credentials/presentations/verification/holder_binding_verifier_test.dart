import 'package:ssi/src/credentials/presentations/verification/holder_binding_verifier.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  group('HolderBindingVerifier', () {
    test('should succeed when VC holder matches VP holder', () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithFullDelegationVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
      expect(result.warnings, isEmpty);
    });

    test('should fail when VC holder does not match VP holder', () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.invalidV1VpString);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors.length, 1);
      expect(result.errors.first,
          'Missing delegation VC from: did:key:zQ3shjgjhNvjBGseaMQW9fKHMUtmf9oDU8LQNPa1Sxf79MJnf');
    });

    test(
        'should succeed when VC has no holder but credentialSubject.id matches VP holder',
        () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.vpWithMatchingCredentialSubject);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, <String>[]);
    });

    test(
        'should fail when VC has no holder and credentialSubject.id does not match VP holder',
        () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures
              .vpWithMismatchingCredentialSubject);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors.length, 1);
      expect(result.errors.first,
          'VC claimid:2b249d9d93f38e3a subject IDs [did:key:zQ3shjgjhNvjBGseaMQW9fKHMUtmf9oDU8LQNPa1Sxf79MJnf] do not include VP holder did:key:zQ3shU4NCP9HmcHa4HNkwJzWgW7LepocEcCgHvgDfeLqggoVf');
    });
    test('should fail when VC has no holder and no credentialSubject.id',
        () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.vpWithNoCredentialSubject);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors.length, 1);
      expect(result.errors.first,
          'VC claimid:2b249d9d93f38e3a has no valid credentialSubject IDs');
    });

    // Delegation tests
    test('should succeed with full delegation', () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithFullDelegationVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('should succeed with restricted delegation', () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpWithRestrictedDelegationVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('should succeed with multiple delegations', () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures
              .v1VpWithMultiDelegationRestricted);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('should succeed with mixed delegation levels', () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures
              .v1VpWithMultiDelegationMixed);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('should fail when delegation VC is missing for external holder',
        () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures
              .v1VpWithMissingDelegationVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors.length, 1);
      expect(
          result.errors.first, contains('Missing delegation VC from:'));
    });

    test('should fail when delegation level is invalid', () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures
              .v1VpWithInvalidDelegationLevel);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors.length, 1);
      expect(result.errors.first, contains('Invalid delegation level:'));
    });

    test(
        'should fail when delegation VC has unexpected credentials in restricted mode',
        () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures
              .v1VpWithUnexpectedDelegatedVC);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors.length, 1);
      expect(
          result.errors.first, contains('Unexpected VCs in the Delegation VC:'));
    });

    test('should fail when delegation VC holder does not match VP holder',
        () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures
              .v1VpWithInvalidDelegationHolder);
      final result = await verifier.verify(vp);
      expect(result.isValid, false);
      expect(result.errors.length, 1);
      expect(result.errors.first,
          contains('Delegation VC delegation-extra holder did:key:anotherholder does not match VP holder'));
    });

    test('should succeed when VC has no holder field but has delegation',
        () async {
      final verifier = HolderBindingVerifier();
      final vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v2VpWithMissingHolder);
      final result = await verifier.verify(vp);
      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });
  });
}
