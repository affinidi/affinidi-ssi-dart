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
          'VC claimid:2b249d9d93f38e3a holder did:key:zQ3shjgjhNvjBGseaMQW9fKHMUtmf9oDU8LQNPa1Sxf79MJnf does not match VP holder did:key:zQ3shU4NCP9HmcHa4HNkwJzWgW7LepocEcCgHvgDfeLqggoVf');
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
  });
}
