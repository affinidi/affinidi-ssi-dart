import 'dart:convert';
import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/verifiable_credentials_data_fixtures.dart';
import '../../test_utils.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  group('Test Linked Data VC DM2 issuance', () {
    test('Create and verify proof', () async {
      final signer = await initSigner(seed);

      final unsignedCredential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([
          dmV2ContextUrl,
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
        credentialSchema: [
          MutableCredentialSchema(
              id: Uri.parse('https://schema.affinidi.com/UserProfileV1-0.json'),
              type: 'JsonSchemaValidator2018')
        ],
        validFrom: DateTime.now(),
        validUntil: DateTime.now().add(const Duration(days: 365)),
        issuer: Issuer.uri(signer.did),
      );

      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );
      final issuedCredential = await LdVcDm2Suite().issue(
          unsignedData: VcDataModelV2.fromMutable(unsignedCredential),
          proofGenerator: proofGenerator);

      final verificationResult =
          await UniversalVerifier().verify(issuedCredential);

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('V2 fixture verify', () async {
      final unsigned = LdVcDm2Suite().parse(VerifiableCredentialDataFixtures
          .credentialWithValidProofDataModelV20String);
      // final issuedCredential = await LdVcDm1Suite().issue(unsigned, signer);

      final validationResult = await LdVcDm2Suite().verifyIntegrity(unsigned);

      expect(validationResult, true);
    });
  });

  group('Issuer/proof DID cross-check (LdBaseSuite VC DM2)', () {
    test('issue() throws when unsigned issuer DID differs from signer DID',
        () async {
      final signer = await initSigner(seed);

      final unsignedCredential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('uuid:issuer-mismatch'),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subject'})
        ],
        // mismatch - issuer DID != signer DID
        issuer: Issuer.uri('did:example:not-${signer.did}'),
      );

      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);

      expect(
        () async => LdVcDm2Suite().issue(
          unsignedData: VcDataModelV2.fromMutable(unsignedCredential),
          proofGenerator: proofGenerator,
        ),
        throwsA(
          predicate((e) =>
              e is SsiException &&
              e.code == SsiExceptionType.invalidJson.code &&
              e.message.toLowerCase().contains('issuer mismatch')),
        ),
      );
    });

    test(
        'verifyIntegrity() throws when issuer DID mutated to not match proof VM DID',
        () async {
      final signer = await initSigner(seed);

      // issue a valid credential first (issuer == signer DID)
      final unsignedCredential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([dmV2ContextUrl]),
        id: Uri.parse('uuid:will-mutate'),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subject'})
        ],
        issuer: Issuer.uri(signer.did),
      );
      final proofGenerator = Secp256k1Signature2019Generator(signer: signer);
      final issuedCredential = await LdVcDm2Suite().issue(
        unsignedData: VcDataModelV2.fromMutable(unsignedCredential),
        proofGenerator: proofGenerator,
      );

      // mutate issuer DID in the serialized form
      final mutated = issuedCredential.toJson();
      mutated['issuer'] = 'did:example:malicious';

      expect(
        () async {
          final parsed = LdVcDm2Suite().parse(jsonEncode(mutated));
          return LdVcDm2Suite().verifyIntegrity(parsed);
        },
        throwsA(isA<SsiException>()),
      );
    });
  });
}
