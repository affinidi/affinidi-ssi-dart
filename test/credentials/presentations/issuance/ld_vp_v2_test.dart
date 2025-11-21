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

    test(
        'should envelope SD-JWT VCs as EnvelopedVerifiableCredential objects in V2 presentations',
        () async {
      // Create a VP V2 containing an SD-JWT VC
      final v2Vp = MutableVpDataModelV2(
          context: [dmV2ContextUrl],
          id: Uri.parse('testVpV2WithSdJwt'),
          type: {'VerifiablePresentation'},
          holder: MutableHolder.uri(signer.did),
          verifiableCredential: [sdjwtV2VC]);

      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );
      final issuedPresentation = await LdVpDm2Suite().issue(
          unsignedData: VpDataModelV2.fromMutable(v2Vp),
          proofGenerator: proofGenerator);

      expect(issuedPresentation, isNotNull);
      expect(issuedPresentation.verifiableCredential, hasLength(1));

      // Convert VP to JSON to inspect the structure
      final vpJson = issuedPresentation.toJson();
      final vcArray = vpJson['verifiableCredential'] as List;
      expect(vcArray, hasLength(1));

      final envelopedVc = vcArray[0] as Map<String, dynamic>;

      // Verify the SD-JWT VC is properly enveloped per VC Data Model V2 spec:
      // "The value MUST be one or more verifiable credential
      // and/or enveloped verifiable credential objects (the values MUST NOT
      // be non-object values such as numbers, strings, or URLs)"

      // Verify it's an object (not a string)
      expect(envelopedVc, isA<Map<String, dynamic>>());

      // Verify it has the required @context
      expect(envelopedVc, containsPair('@context', anything));
      final context = envelopedVc['@context'];
      expect(context, isA<List>());
      expect(context, contains(dmV2ContextUrl));

      // Verify it has the EnvelopedVerifiableCredential type
      expect(envelopedVc, containsPair('type', anything));
      final type = envelopedVc['type'];
      expect(type, isA<List>());
      expect(type, contains('EnvelopedVerifiableCredential'));

      // Verify the id is a data URL containing the SD-JWT
      expect(envelopedVc, containsPair('id', anything));
      final id = envelopedVc['id'] as String;
      expect(id, startsWith('data:application/vc+sd-jwt,'));

      // Verify the SD-JWT string is embedded in the data URL
      expect(id, contains(sdjwtV2VC.serialized));

      // Verify the envelope structure matches the spec example:
      // {
      //   "@context": ["https://www.w3.org/ns/credentials/v2"],
      //   "id": "data:application/vc+sd-jwt,QzVjV...RMjU",
      //   "type": ["EnvelopedVerifiableCredential"]
      // }
    });

    // TODO: Add failure tests once validations are added to issuance.
  });
}
