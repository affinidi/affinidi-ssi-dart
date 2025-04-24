import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/credential_subject.dart';
import 'package:ssi/src/credentials/models/holder.dart';
import 'package:ssi/src/credentials/models/issuer.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart';
import 'package:ssi/src/credentials/proof/embedded_proof.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  late final DidSigner signer;

  setUpAll(() async {
    signer = await initSigner(seed);
  });
  group('verify embedded proof', () {
    final unsignedCredential = MutableVcDataModelV1(
      context: [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.affinidi.com/UserProfileV1-0.jsonld"
      ],
      id: "uuid:123456abcd",
      type: ["VerifiableCredential", "UserProfile"],
      credentialSubject: CredentialSubject(claims: {
        "Fname": "Fname",
        "Lname": "Lame",
        "Age": "22",
        "Address": "Eihhornstr"
      }),
      holder: Holder(id: Uri.parse("did:example:1")),
      credentialSchema: [
        CredentialSchema.fromJson({
          "id": "https://schema.affinidi.com/UserProfileV1-0.json",
          "type": "JsonSchemaValidator2018"
        })
      ],
      issuanceDate: DateTime.now(),
      issuer: Issuer(
          id: 'did:key:aaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaabaaaa'),
    );

    test('should create proof and verify successfully', () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
          signer: signer,
        ),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
          customDocumentLoader: testLoadDocument,
          issuerDid: signer.did,
        ),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with future expiry and verify successfully',
        () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
            signer: signer, expires: DateTime.parse('3024-01-01T12:00:01Z')),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
            customDocumentLoader: testLoadDocument, issuerDid: signer.did),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with past expiry and throw expire error',
        () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
            signer: signer, expires: DateTime.now()),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
            customDocumentLoader: testLoadDocument,
            issuerDid: signer.did,
            getNow: () => DateTime.parse('3024-01-01T12:00:01Z')),
      );

      expect(verificationResult.isValid, false);
      expect(verificationResult.errors, ['proof is no longer valid']);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with domain and challenge and pass verification',
        () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
            signer: signer,
            expires: DateTime.parse('3024-01-01T12:00:01Z'),
            domain: ['example.com'],
            challenge: 'test-challenge'),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
            customDocumentLoader: testLoadDocument,
            issuerDid: signer.did,
            domain: ['example.com'],
            challenge: 'test-challenge'),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test(
        'should create proof with domain and challenge and check validation against verification options',
        () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
            signer: signer,
            expires: DateTime.parse('3024-01-01T12:00:01Z'),
            domain: ['example.com'],
            challenge: 'test-challenge'),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
            customDocumentLoader: testLoadDocument,
            issuerDid: signer.did,
            domain: ['example1.com'],
            challenge: 'test-challenge'),
      );

      expect(verificationResult.isValid, false);
      expect(verificationResult.errors, ['invalid or missing proof.domain']);
      expect(verificationResult.warnings, isEmpty);
    });

    test(
        'should create proof with domain array and challenge and check validation against verification options',
        () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
            signer: signer,
            expires: DateTime.parse('3024-01-01T12:00:01Z'),
            domain: ['example.com', 'example1.com'],
            challenge: 'test-challenge'),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
            customDocumentLoader: testLoadDocument,
            issuerDid: signer.did,
            domain: ['example.com', 'example1.com'],
            challenge: 'test-challenge'),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with domain and empty challenge and throw error',
        () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
          signer: signer,
          expires: DateTime.parse('3024-01-01T12:00:01Z'),
          domain: ['example.com'],
        ),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
            customDocumentLoader: testLoadDocument, issuerDid: signer.did),
      );

      expect(verificationResult.isValid, false);
      expect(verificationResult.errors, ['invalid or missing proof.challenge']);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with empty domain and throw error', () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
          signer: signer,
          expires: DateTime.parse('3024-01-01T12:00:01Z'),
          challenge: 'test-challenge',
        ),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
            customDocumentLoader: testLoadDocument, issuerDid: signer.did),
      );

      expect(verificationResult.isValid, false);
      expect(verificationResult.errors,
          ['proof.challenge must be accompanied by proof.domain']);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with empty domain and throw error', () async {
      final proofSuite = EcdsaSecp256k1Signature2019();
      final proof = await proofSuite.createProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019CreateOptions(
          signer: signer,
          expires: DateTime.parse('3024-01-01T12:00:01Z'),
          challenge: 'test-challenge',
        ),
      );

      unsignedCredential.proof = [EmbeddedProof.fromJson(proof.toJson())];

      final verificationResult = await proofSuite.verifyProof(
        unsignedCredential.toJson(),
        EcdsaSecp256k1Signature2019VerifyOptions(
            customDocumentLoader: testLoadDocument, issuerDid: signer.did),
      );

      expect(verificationResult.isValid, false);
      expect(verificationResult.errors,
          ['proof.challenge must be accompanied by proof.domain']);
      expect(verificationResult.warnings, isEmpty);
    });
  });
}
