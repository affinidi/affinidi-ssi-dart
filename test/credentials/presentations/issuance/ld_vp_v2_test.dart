import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../../test_utils.dart';

void main() async {
  final testSeed = Uint8List.fromList(List.generate(32, (index) => index + 1));

  final ldV1VC = UniversalParser.parse(VerifiableCredentialDataFixtures
      .credentialWithValidProofDataModelV11JsonEncoded);
  final ldV2VC = UniversalParser.parse(VerifiableCredentialDataFixtures
      .credentialWithValidProofDataModelV20String);
  final sdjwtV2VC =
      UniversalParser.parse(VerifiableCredentialDataFixtures.sdJwtWithValidSig);

  final signer = await initSigner(testSeed);

  group('VP LD V2 Issuance', () {
    test('should be able to create a presentation containing V2 compatible VCs',
        () async {
      final v2Vp = MutableVpDataModelV2(
          context: [dmV2ContextUrl],
          id: Uri.parse('testVpV2'),
          type: {'VerifiablePresentation'},
          holder: MutableHolder.uri(signer.did),
          verifiableCredential: [ldV1VC, ldV2VC, sdjwtV2VC]);

      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );
      final issuedPresentation = await LdVpDm2Suite().issue(
          unsignedData: VpDataModelV2.fromMutable(v2Vp),
          proofGenerator: proofGenerator);

      expect(issuedPresentation, isNotNull);
      expect(issuedPresentation.serialized, isNotNull);
      expect(issuedPresentation.serialized, isA<String>());
      expect(issuedPresentation.holder, isNotNull);
      expect(issuedPresentation.context.first, isNotEmpty);
      expect(dmV2ContextUrl, isIn(issuedPresentation.context));
      expect(issuedPresentation.proof, isNotEmpty);
    });

    // TODO: Add failure tests once validations are added to issuance.
  });
}
