import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/credentials/presentations/linked_data/ld_vp_dm_v1_suite.dart';
import 'package:ssi/src/credentials/presentations/models/v1/vp_data_model_v1.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../../test_utils.dart';

void main() async {
  final testSeed = Uint8List.fromList(
      utf8.encode('test seed for deterministic key generation'));

  final ldV1VC = UniversalParser.parse(VerifiableCredentialDataFixtures
      .credentialWithProofDataModelV11JsonEncoded);
  final jwtV1VC = UniversalParser.parse(
      VerifiableCredentialDataFixtures.jwtCredentialDataModelV11);

  final signer = await initSigner(testSeed);

  group('VP LD V1 Issuance', () {
    test('should be able to create a presentation containing V1 compatible VCs',
        () async {
      final v1Vp = MutableVpDataModelV1(
          context: [MutableVpDataModelV1.contextUrl],
          id: 'testVpV1',
          type: ['VerifiablePresentation'],
          verifiableCredential: [ldV1VC, jwtV1VC]);

      var issuedCredential = await LdVpDm1Suite().issue(v1Vp, signer);

      expect(issuedCredential, isNotNull);
      expect(issuedCredential.serialized, isNotNull);
      expect(issuedCredential.serialized, isA<String>());
      expect(MutableVpDataModelV1.contextUrl, isIn(issuedCredential.context));
      expect(issuedCredential.holder, isNotEmpty);
      expect(issuedCredential.proof, isNotEmpty);
    });

    // TODO: Add failure tests once validations are added to issuance.
  });
}
