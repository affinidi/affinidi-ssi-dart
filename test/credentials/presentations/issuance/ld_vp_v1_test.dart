import 'dart:typed_data';

import 'package:ssi/src/credentials/models/field_types/holder.dart';
import 'package:ssi/src/credentials/presentations/linked_data/ld_vp_dm_v1_suite.dart';
import 'package:ssi/src/credentials/presentations/models/v1/vp_data_model_v1.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../../test_utils.dart';

void main() async {
  final testSeed = Uint8List.fromList(List.generate(32, (index) => index + 1));

  final ldV1VC = UniversalParser.parse(VerifiableCredentialDataFixtures
      .credentialWithValidProofDataModelV11JsonEncoded);
  final jwtV1VC = UniversalParser.parse(
      VerifiableCredentialDataFixtures.jwtCredentialDataModelV11);

  final signer = await initSigner(testSeed);

  group('VP LD V1 Issuance', () {
    test('should be able to create a presentation containing V1 compatible VCs',
        () async {
      final v1Vp = MutableVpDataModelV1(
          context: [VpDataModelV1.contextUrl],
          id: Uri.parse('testVpV1'),
          type: {'VerifiablePresentation'},
          holder: Holder.uri(signer.did),
          verifiableCredential: [ldV1VC, jwtV1VC]);

      final issuedPresentation = await LdVpDm1Suite()
          .issue(VpDataModelV1.fromJson(v1Vp.toJson()), signer);

      expect(issuedPresentation, isNotNull);
      expect(issuedPresentation.serialized, isNotNull);
      expect(issuedPresentation.serialized, isA<String>());
      expect(VpDataModelV1.contextUrl, isIn(issuedPresentation.context));
      expect(issuedPresentation.holder, isNotNull);
      expect(issuedPresentation.proof, isNotEmpty);
    });

    // TODO: Add failure tests once validations are added to issuance.
  });
}
