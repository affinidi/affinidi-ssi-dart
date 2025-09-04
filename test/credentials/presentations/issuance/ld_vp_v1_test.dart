import 'dart:typed_data';

import 'package:ssi/src/credentials/models/field_types/context.dart';
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
          context: MutableJsonLdContext.fromJson([dmV1ContextUrl]),
          id: Uri.parse('testVpV1'),
          type: {'VerifiablePresentation'},
          holder: MutableHolder.uri(signer.did),
          verifiableCredential: [ldV1VC, jwtV1VC]);

      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );
      final issuedPresentation = await LdVpDm1Suite().issue(
          unsignedData: VpDataModelV1.fromMutable(v1Vp),
          proofGenerator: proofGenerator);
      expect(issuedPresentation, isNotNull);
      expect(issuedPresentation.serialized, isNotNull);
      expect(issuedPresentation.serialized, isA<String>());
      expect(dmV1ContextUrl, isIn(issuedPresentation.context.uris.first.toString()));
      expect(issuedPresentation.holder, isNotNull);
      expect(issuedPresentation.proof, isNotEmpty);
    });

    // TODO: Add failure tests once validations are added to issuance.
  });
}
