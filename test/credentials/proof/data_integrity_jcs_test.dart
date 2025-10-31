import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/credentials/models/field_types/context.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../../fixtures/jcs_test_vectors.dart';

void main() {
  group('Digital Bazaar JCS Test Vectors', () {
    test('Verify ecdsa-jcs-2019 test vector', () async {
      // Use shared test vector
      final json = JcsTestVectors.ecdsaJcs2019TestVector;

      // Validate test vector structure
      expect(json['proof']['cryptosuite'], 'ecdsa-jcs-2019');
      expect(
          json['proof']['proofValue'], startsWith('z')); // base58-btc multibase
      expect(json['issuer'], startsWith('did:key:zDnaeo')); // P-256 key format

      // Validate signature length (ECDSA P-256 signature = 64 bytes: 32 bytes r + 32 bytes s)
      final signature =
          base58BitcoinDecode(json['proof']['proofValue'].substring(1));
      expect(signature.length, 64);

      // Extract issuer DID
      final issuerDid = json['issuer'] as String;

      // Create verifier
      final verifier = DataIntegrityEcdsaJcsVerifier(verifierDid: issuerDid);

      // Verify the credential
      final result = await verifier.verify(json);

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('Verify eddsa-jcs-2022 test vector', () async {
      // Use shared test vector
      final json = JcsTestVectors.eddsaJcs2022TestVector;

      // Validate test vector structure
      expect(json['proof']['cryptosuite'], 'eddsa-jcs-2022');
      expect(
          json['proof']['proofValue'], startsWith('z')); // base58-btc multibase
      expect(json['issuer'], startsWith('did:key:z6Mkr')); // Ed25519 key format

      // Validate signature length (EdDSA Ed25519 signature = 64 bytes: 32 bytes R + 32 bytes S)
      final signature =
          base58BitcoinDecode(json['proof']['proofValue'].substring(1));
      expect(signature.length, 64);

      // Extract issuer DID
      final issuerDid = json['issuer'] as String;

      // Create verifier
      final verifier = DataIntegrityEddsaJcsVerifier(verifierDid: issuerDid);

      // Verify the credential
      final result = await verifier.verify(json);

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('Reject invalid multibase encoding', () async {
      final json =
          Map<String, dynamic>.from(JcsTestVectors.ecdsaJcs2019TestVector);
      final proof =
          Map<String, dynamic>.from(json['proof'] as Map<String, dynamic>);
      json['proof'] = proof;

      // Change multibase prefix from 'z' to 'f'
      final originalProofValue = proof['proofValue'] as String;
      proof['proofValue'] = 'f${originalProofValue.substring(1)}';

      final issuerDid = json['issuer'] as String;
      final verifier = DataIntegrityEcdsaJcsVerifier(verifierDid: issuerDid);

      // Should throw SsiException for invalid encoding
      expect(() => verifier.verify(json), throwsA(isA<SsiException>()));
    });

    /// Test helper for multibase encoding verification
    Future<void> testMultibaseEncoding({
      required MultiBase encoding,
      required String expectedPrefix,
      int seedStart = 1,
    }) async {
      // Create a test wallet and generate key
      final seed =
          Uint8List.fromList(List.generate(32, (index) => index + seedStart));
      final wallet = Bip32Ed25519Wallet.fromSeed(seed);
      final keyPair = await wallet.generateKey(keyId: "m/0'/0'");
      final doc = DidKey.generateDocument(keyPair.publicKey);

      final credential = MutableVcDataModelV2(
        context: MutableJsonLdContext.fromJson([
          'https://www.w3.org/ns/credentials/v2',
        ]),
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subject'})
        ],
        issuer: Issuer.uri(doc.id),
      );

      final signer = DidSigner(
        did: doc.id,
        didKeyId: doc.verificationMethod[0].id,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ed25519,
      );

      // Generate proof with specified encoding
      final generator = DataIntegrityEddsaJcsGenerator(
        signer: signer,
        proofValueMultiBase: encoding,
      );

      final proof = await generator.generate(credential.toJson());
      final credentialWithProof = credential.toJson();
      credentialWithProof['proof'] = proof.toJson();

      // Verify the proofValue uses expected prefix
      expect(proof.proofValue, startsWith(expectedPrefix));

      // Verify the credential
      final verifier = DataIntegrityEddsaJcsVerifier(
        verifierDid: doc.id,
      );
      final result = await verifier.verify(credentialWithProof);

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    }

    test('Support base64url multibase encoding (u prefix)', () async {
      await testMultibaseEncoding(
        encoding: MultiBase.base64UrlNoPad,
        expectedPrefix: 'u',
      );
    });

    test('Support both base58 and base64url in same verification flow',
        () async {
      final encodings = [
        {'encoding': MultiBase.base58bitcoin, 'prefix': 'z'},
        {'encoding': MultiBase.base64UrlNoPad, 'prefix': 'u'},
      ];

      for (final config in encodings) {
        await testMultibaseEncoding(
          encoding: config['encoding'] as MultiBase,
          expectedPrefix: config['prefix'] as String,
          seedStart: 5,
        );
      }
    });

    test(
        'Verifier rejects when verifierDid mismatches proof.verificationMethod DID',
        () async {
      final json =
          Map<String, dynamic>.from(JcsTestVectors.ecdsaJcs2019TestVector);
      // expect((json['proof'] as Map<String, dynamic>)['verificationMethod'], startsWith(json['issuer'] as String));

      final wrongIssuerDid = 'did:example:someone-else';
      final verifier =
          DataIntegrityEcdsaJcsVerifier(verifierDid: wrongIssuerDid);

      final result = await verifier.verify(json);

      expect(result.isValid, isFalse);
      expect(
        result.errors.join(' ').toLowerCase(),
        contains('issuer did does not match'),
      );
    });
  });
}
