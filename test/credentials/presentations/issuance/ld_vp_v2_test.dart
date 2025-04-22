import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/credentials/presentations/linked_data/ld_vp_dm_v2_suite.dart';
import 'package:ssi/src/credentials/presentations/models/v2/vp_data_model_v2.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../../test_utils.dart';

void main() async {
  final testSeed = Uint8List.fromList(
      utf8.encode('test seed for deterministic key generation'));

  final ldV1VC = UniversalParser.parse(VerifiableCredentialDataFixtures
      .credentialWithValidProofDataModelV11JsonEncoded);
  final ldV2VC = UniversalParser.parse(VerifiableCredentialDataFixtures
      .expiringCredentialWithValidProofDataModelV20String);
  final sdjwtV2VC =
      UniversalParser.parse(VerifiableCredentialDataFixtures.sdJwtWithValidSig);

  final signer = await initSigner(testSeed);

  group('VP LD V2 Issuance', () {
    test('should be able to create a presentation containing V2 compatible VCs',
        () async {
      final v2Vp = MutableVpDataModelV2(
          context: [MutableVpDataModelV2.contextUrl],
          id: 'testVpV2',
          type: ['VerifiablePresentation'],
          verifiableCredential: [ldV1VC, ldV2VC, sdjwtV2VC]);

      var issuedCredential = await LdVpDm2Suite().issue(v2Vp, signer);

      expect(issuedCredential, isNotNull);
      expect(issuedCredential.serialized, isNotNull);
      expect(issuedCredential.serialized, isA<String>());
      expect(issuedCredential.holder, isNotEmpty);
      expect(issuedCredential.context.first, isNotEmpty);
      expect(MutableVpDataModelV2.contextUrl, isIn(issuedCredential.context));
      expect(issuedCredential.proof, isNotEmpty);
    });

    // TODO: Add failure tests once validations are added to issuance.
  });
}
