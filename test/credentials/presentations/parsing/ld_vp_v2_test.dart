import 'package:ssi/src/credentials/linked_data/ld_dm_v1_suite.dart';
import 'package:ssi/src/credentials/linked_data/ld_dm_v2_suite.dart';
import 'package:ssi/src/credentials/models/v2/vc_data_model_v2.dart';
import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:ssi/src/credentials/sdjwt/sdjwt_dm_v2_suite.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  group('VP LD V2 Parsing', () {
    test(
        'should be able to parse a V2 presentation containing V2 compatible VCs',
        () async {
      final v2Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v2VpString);

      expect(v2Vp, isNotNull);
      expect(v2Vp.serialized, isNotNull);
      expect(v2Vp.serialized, isA<String>());
      expect(dmV2ContextUrl, isIn(v2Vp.context));
      expect(v2Vp.holder, isNotNull);
      expect(v2Vp.proof, isNotEmpty);
      expect(v2Vp.verifiableCredential.length, 3);
      expect(v2Vp.verifiableCredential[0], isA<LdVcDataModelV1>());
      expect(v2Vp.verifiableCredential[1], isA<LdVcDataModelV2>());
      expect(v2Vp.verifiableCredential[2], isA<SdJwtDataModelV2>());
    });

    test(
        'should correctly parse enveloped SD-JWT VCs from V2 presentations per spec',
        () async {
      // Parse the VP that contains enveloped credentials
      final v2Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v2VpString);

      // Find the SD-JWT VC (it should be the 3rd credential)
      final sdJwtVc = v2Vp.verifiableCredential[2];
      expect(sdJwtVc, isA<SdJwtDataModelV2>());

      // Verify the parsed SD-JWT VC has valid properties
      expect(sdJwtVc.issuer, isNotNull);
      expect(sdJwtVc.type, isNotEmpty);
      expect(sdJwtVc.type, contains('VerifiableCredential'));
      expect(sdJwtVc.serialized, isNotNull);
      expect(sdJwtVc.serialized, isA<String>());

      // Verify the serialized form is the raw SD-JWT (not the envelope)
      expect(
          sdJwtVc.serialized, isNot(contains('EnvelopedVerifiableCredential')));
      expect(sdJwtVc.serialized, isNot(startsWith('{')));

      // Verify that when we re-serialize the VP, the SD-JWT is enveloped again
      final vpJson = v2Vp.toJson();
      final vcArray = vpJson['verifiableCredential'] as List;
      final envelopedVc = vcArray[2] as Map<String, dynamic>;

      // Per VC Data Model V2 spec Section 4.13, the credential in the VP
      // MUST be an object (not a string)
      expect(envelopedVc, isA<Map<String, dynamic>>());
      expect(envelopedVc['type'], contains('EnvelopedVerifiableCredential'));
      expect(envelopedVc['id'], startsWith('data:application/vc+sd-jwt,'));
      expect(envelopedVc['@context'], contains(dmV2ContextUrl));
    });
  });
}
