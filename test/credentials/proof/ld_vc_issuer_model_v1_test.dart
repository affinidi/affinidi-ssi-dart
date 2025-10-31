import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../test_utils.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final signer = await initSigner(seed);

  group('Test Linked Data VC issuance', () {
    test('Create and verify proof', () async {
      final unsignedCredential = MutableVcDataModelV1(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/2018/credentials/v1',
          'https://schema.affinidi.com/UserProfileV1-0.jsonld'
        ]),
        id: Uri.parse('uuid:123456abcd'),
        type: {'VerifiableCredential', 'UserProfile'},
        credentialSubject: [
          MutableCredentialSubject({
            'Fname': 'Fname',
            'Lname': 'Lame',
            'Age': '22',
            'Address': 'Eihhornstr'
          })
        ],
        holder: MutableHolder.uri('did:example:1'),
        credentialSchema: [
          MutableCredentialSchema(
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        issuanceDate: DateTime.now(),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      final proofVerifier =
          Secp256k1Signature2019Verifier(issuerDid: signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('CWE issued must verify', () async {
      final proofVerifier = Secp256k1Signature2019Verifier(
          issuerDid: cweResponse['issuer'] as String);
      final verificationResult = await proofVerifier.verify(cweResponse);

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('LdVCDM1 fixture VC verify', () async {
      final unsigned = LdVcDm1Suite().parse(VerifiableCredentialDataFixtures
          .credentialWithValidProofDataModelV11JsonEncoded);
      // final issuedCredential = await LdVcDm1Suite().issue(unsigned, signer);

      final validationResult = await LdVcDm1Suite().verifyIntegrity(unsigned);

      expect(validationResult, true);
    });

    test('LdVCDM1 fixture VC verify', () async {
      final unsigned = MutableVcDataModelV1.fromJson(LdVcDm1Suite()
          .parse(VerifiableCredentialDataFixtures
              .credentialWithValidProofDataModelV11JsonEncoded)
          .toJson());

      unsigned.issuer = MutableIssuer.uri(signer.did);

      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );

      final issuedCredential = await LdVcDm1Suite().issue(
        unsignedData: VcDataModelV1.fromMutable(unsigned),
        proofGenerator: proofGenerator,
      );

      final validationResult =
          await LdVcDm1Suite().verifyIntegrity(issuedCredential);

      expect(validationResult, true);
    });
  });
}

final cweResponse = jsonDecode(
  VerifiableCredentialDataFixtures.ldVcDm1ValidStringFromCwe,
) as Map<String, dynamic>;
