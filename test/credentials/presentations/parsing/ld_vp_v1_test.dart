import 'package:ssi/src/credentials/jwt/jwt_dm_v1_suite.dart';
import 'package:ssi/src/credentials/linked_data/ld_vc_data_model_v1.dart';
import 'package:ssi/src/credentials/presentations/models/v1/mutable_vp_data_model_v1.dart';
import 'package:ssi/src/credentials/presentations/suites/universal_presentation_parser.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_presentations_fixtures.dart';

void main() async {
  group('VP LD V1 Parsing', () {
    test(
        'should be able to parse a V1 presentation containing V1 compatible VCs',
        () async {
      final v1Vp = UniversalPresentationParser.parse(
          VerifiablePresentationDataFixtures.v1VpString);

      expect(v1Vp, isNotNull);
      expect(v1Vp.serialized, isNotNull);
      expect(v1Vp.serialized, isA<String>());
      expect(MutableVpDataModelV1.contextUrl, isIn(v1Vp.context));
      expect(v1Vp.holder, isNotNull);
      expect(v1Vp.proof, isNotEmpty);
      expect(v1Vp.verifiableCredential.length, 2);
      expect(v1Vp.verifiableCredential[0], isA<LdVcDataModelV1>());
      expect(v1Vp.verifiableCredential[1], isA<JwtVcDataModelV1>());
    });
  });
}
