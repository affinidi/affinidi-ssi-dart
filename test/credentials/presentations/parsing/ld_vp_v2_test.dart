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
      expect(dmV2ContextUrl, isIn(v2Vp.context.uris.first.toString()));
      expect(v2Vp.holder, isNotNull);
      expect(v2Vp.proof, isNotEmpty);
      expect(v2Vp.verifiableCredential.length, 3);
      expect(v2Vp.verifiableCredential[0], isA<LdVcDataModelV1>());
      expect(v2Vp.verifiableCredential[1], isA<LdVcDataModelV2>());
      expect(v2Vp.verifiableCredential[2], isA<SdJwtDataModelV2>());
    });
  });
}
