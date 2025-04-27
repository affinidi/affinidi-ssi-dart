import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/linked_data/ld_dm_v1_suite.dart';
import 'package:ssi/src/credentials/models/credential_subject.dart';
import 'package:ssi/src/credentials/models/holder.dart';
import 'package:ssi/src/credentials/models/issuer.dart';
import 'package:ssi/src/credentials/models/v1/vc_data_model_v1.dart';
import 'package:ssi/src/credentials/proof/ecdsa_secp256k1_signature2019_suite.dart';
import 'package:ssi/src/credentials/proof/proof_purpose.dart';
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

    test('should create proof and verify and validate successfully', () async {
      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
      );
      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier =
          Secp256k1Signature2019Verifier(issuerDid: signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());
      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
      final validationResult =
          await proofVerifier.validate(issuedCredential.toJson());
      expect(validationResult.isValid, true);
      expect(validationResult.errors, isEmpty);
      expect(validationResult.warnings, isEmpty);
    });

    test('should create proof with proofPurpose and verify successfully',
        () async {
      final proofGenerator = Secp256k1Signature2019Generator(
          signer: signer, proofPurpose: ProofPurpose.authentication);
      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier =
          Secp256k1Signature2019Verifier(issuerDid: signer.did);

      final verificationResult =
          await proofVerifier.verify(issuedCredential.toJson());
      expect(issuedCredential.proof.first.proofPurpose,
          ProofPurpose.authentication.value);
      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
      final validationResult =
          await proofVerifier.validate(issuedCredential.toJson());
      expect(validationResult.isValid, true);
      expect(validationResult.errors, isEmpty);
      expect(validationResult.warnings, isEmpty);
    });

    test('should create proof with future expiry and verify successfully',
        () async {
      final proofGenerator = Secp256k1Signature2019Generator(
          signer: signer, expires: DateTime.parse('3024-01-01T12:00:01Z'));

      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier =
          Secp256k1Signature2019Verifier(issuerDid: signer.did);
      final verificationResult = await proofVerifier.verify(
        issuedCredential.toJson(),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with past expiry and throw expire error',
        () async {
      final proofGenerator = Secp256k1Signature2019Generator(
          signer: signer, expires: DateTime.now());

      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier = Secp256k1Signature2019Verifier(
          issuerDid: signer.did,
          getNow: () => DateTime.parse('3024-01-01T12:00:01Z'));
      final verificationResult = await proofVerifier.verify(
        issuedCredential.toJson(),
      );
      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
      final validationResult =
          await proofVerifier.validate(issuedCredential.toJson());
      expect(validationResult.isValid, false);
      expect(validationResult.errors, ['proof is no longer valid']);
      expect(validationResult.warnings, isEmpty);
    });

    test(
        'should create proof with domain and challenge and pass verification with verify options',
        () async {
      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
        expires: DateTime.parse('3024-01-01T12:00:01Z'),
        domain: ['example.com'],
        challenge: 'test-challenge',
      );

      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier = Secp256k1Signature2019Verifier(
          issuerDid: signer.did,
          domain: ['example.com'],
          challenge: 'test-challenge');

      final verificationResult = await proofVerifier.verify(
        issuedCredential.toJson(),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with domain and challenge and pass verification',
        () async {
      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
        expires: DateTime.parse('3024-01-01T12:00:01Z'),
        domain: ['example.com'],
        challenge: 'test-challenge',
      );

      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier =
          Secp256k1Signature2019Verifier(issuerDid: signer.did);

      final verificationResult = await proofVerifier.verify(
        issuedCredential.toJson(),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test(
        'should create proof with domain and challenge and check validation against verification options',
        () async {
      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
        expires: DateTime.parse('3024-01-01T12:00:01Z'),
        domain: ['example.com'],
        challenge: 'test-challenge',
      );

      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier = Secp256k1Signature2019Verifier(
          issuerDid: signer.did,
          domain: ['example1.com'],
          challenge: 'test-challenge');

      final verificationResult = await proofVerifier.verify(
        issuedCredential.toJson(),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
      final validationResult =
          await proofVerifier.validate(issuedCredential.toJson());
      expect(validationResult.isValid, false);
      expect(validationResult.errors, ['invalid or missing proof.domain']);
      expect(validationResult.warnings, isEmpty);
    });

    test(
        'should create proof with domain array and challenge and check validation against verification options',
        () async {
      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
        expires: DateTime.parse('3024-01-01T12:00:01Z'),
        domain: ['example.com', 'example1.com'],
        challenge: 'test-challenge',
      );

      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier = Secp256k1Signature2019Verifier(
          issuerDid: signer.did,
          domain: ['example.com', 'example1.com'],
          challenge: 'test-challenge');

      final verificationResult = await proofVerifier.verify(
        issuedCredential.toJson(),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
    });

    test('should create proof with domain and empty challenge and throw error',
        () async {
      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
        expires: DateTime.parse('3024-01-01T12:00:01Z'),
        domain: ['example.com'],
      );

      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier =
          Secp256k1Signature2019Verifier(issuerDid: signer.did);

      final verificationResult = await proofVerifier.verify(
        issuedCredential.toJson(),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
      final validationResult =
          await proofVerifier.validate(issuedCredential.toJson());
      expect(validationResult.isValid, false);
      expect(validationResult.errors, ['invalid or missing proof.challenge']);
      expect(validationResult.warnings, isEmpty);
    });

    test('should create proof with empty domain and throw error', () async {
      final proofGenerator = Secp256k1Signature2019Generator(
        signer: signer,
        expires: DateTime.parse('3024-01-01T12:00:01Z'),
        challenge: 'test-challenge',
      );

      final issuedCredential = await LdVcDm1Suite().issue(
          unsignedData: unsignedCredential,
          issuer: signer.did,
          proofGenerator: proofGenerator);

      final proofVerifier =
          Secp256k1Signature2019Verifier(issuerDid: signer.did);

      final verificationResult = await proofVerifier.verify(
        issuedCredential.toJson(),
      );

      expect(verificationResult.isValid, true);
      expect(verificationResult.errors, isEmpty);
      expect(verificationResult.warnings, isEmpty);
      final validationResult =
          await proofVerifier.validate(issuedCredential.toJson());
      expect(validationResult.isValid, false);
      expect(validationResult.errors,
          ['proof.challenge must be accompanied by proof.domain']);
      expect(validationResult.warnings, isEmpty);
    });
  });
}
