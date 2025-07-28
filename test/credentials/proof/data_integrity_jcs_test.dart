import 'dart:convert';
import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

// Digital Bazaar test vectors embedded directly
const ecdsaJcs2019TestVector = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2'
  ],
  'id': 'urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33',
  'type': ['VerifiableCredential', 'AlumniCredential'],
  'name': 'Alumni Credential',
  'description': 'A minimum viable example of an Alumni Credential.',
  'issuer': 'did:key:zDnaeoWd5aKSeZ8QAimcVrLGEU2SnWCrY4wQneAAk5NhQyn8U',
  'validFrom': '2023-01-01T00:00:00Z',
  'credentialSubject': {
    'id': 'did:example:abcdefgh',
    'alumniOf': 'The School of Examples'
  },
  'proof': {
    'type': 'DataIntegrityProof',
    'created': '2023-02-24T23:36:38Z',
    'verificationMethod':
        'did:key:zDnaeoWd5aKSeZ8QAimcVrLGEU2SnWCrY4wQneAAk5NhQyn8U#zDnaeoWd5aKSeZ8QAimcVrLGEU2SnWCrY4wQneAAk5NhQyn8U',
    'cryptosuite': 'ecdsa-jcs-2019',
    'proofPurpose': 'assertionMethod',
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    'proofValue':
        'z42wCWvyMAGP77wYLTyciWjhCbuFrRzS93iMDEg3GWUaDUTnc27uQYHg7p6JwA2Pg36JS2Ng1RuDgbLwNhGMDHaMc'
  }
};

const eddsaJcs2022TestVector = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2'
  ],
  'id': 'urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33',
  'type': ['VerifiableCredential', 'AlumniCredential'],
  'name': 'Alumni Credential',
  'description': 'A minimum viable example of an Alumni Credential.',
  'issuer': 'did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2',
  'validFrom': '2023-01-01T00:00:00Z',
  'credentialSubject': {
    'id': 'did:example:abcdefgh',
    'alumniOf': 'The School of Examples'
  },
  'proof': {
    'type': 'DataIntegrityProof',
    'created': '2023-02-24T23:36:38Z',
    'verificationMethod':
        'did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2',
    'cryptosuite': 'eddsa-jcs-2022',
    'proofPurpose': 'assertionMethod',
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2'
    ],
    'proofValue':
        'z5EhYRJkfPLkoT92FPXN8KK6M9rsBhq3xs19GBSsA6VdNYH4QMKSyNuA2Gfznz9QthVD7Rz3HTAfqxxay23htUpTg'
  }
};

void main() {
  group('Digital Bazaar JCS Test Vectors', () {
    test('Verify ecdsa-jcs-2019 test vector', () async {
      // Use embedded test vector
      final json = jsonDecode(jsonEncode(ecdsaJcs2019TestVector));

      // Validate test vector structure
      expect(json['proof']['cryptosuite'], 'ecdsa-jcs-2019');
      expect(
          json['proof']['proofValue'], startsWith('z')); // base58-btc multibase
      expect(json['issuer'], startsWith('did:key:zDnaeo')); // P-256 key format

      // Validate signature length (P-256 = 64 bytes)
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
      // Use embedded test vector
      final json = jsonDecode(jsonEncode(eddsaJcs2022TestVector));

      // Validate test vector structure
      expect(json['proof']['cryptosuite'], 'eddsa-jcs-2022');
      expect(
          json['proof']['proofValue'], startsWith('z')); // base58-btc multibase
      expect(json['issuer'], startsWith('did:key:z6Mkr')); // Ed25519 key format

      // Validate signature length (Ed25519 = 64 bytes)
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
      final json = jsonDecode(jsonEncode(ecdsaJcs2019TestVector));

      // Change multibase prefix from 'z' to 'f'
      final originalProofValue = json['proof']['proofValue'] as String;
      json['proof']['proofValue'] = 'f${originalProofValue.substring(1)}';

      final issuerDid = json['issuer'] as String;
      final verifier = DataIntegrityEcdsaJcsVerifier(verifierDid: issuerDid);

      // Should throw SsiException for invalid encoding
      expect(() => verifier.verify(json), throwsA(isA<SsiException>()));
    });

    test('Support base64url multibase encoding (u prefix)', () async {
      // Create a test wallet and generate key
      final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
      final wallet = Bip32Ed25519Wallet.fromSeed(seed);
      final keyPair = await wallet.generateKey(keyId: "m/0'/0'");
      final doc = DidKey.generateDocument(keyPair.publicKey);

      final credential = MutableVcDataModelV2(
        context: [
          'https://www.w3.org/ns/credentials/v2',
        ],
        type: {'VerifiableCredential'},
        credentialSubject: [
          MutableCredentialSubject({'id': 'did:example:subject'})
        ],
        issuer: Issuer.uri(doc.id),
      );

      // Create signer with Ed25519 key
      final signer = DidSigner(
        did: doc.id,
        didKeyId: doc.verificationMethod[0].id,
        keyPair: keyPair,
        signatureScheme: SignatureScheme.ed25519,
      );

      // Generate proof with base64url encoding
      final generator = DataIntegrityEddsaJcsGenerator(
        signer: signer,
        proofValueMultiBase: MultiBase.base64UrlNoPad,
      );

      final proof = await generator.generate(credential.toJson());
      final credentialWithProof = credential.toJson();
      credentialWithProof['proof'] = proof.toJson();

      // Verify the proofValue uses 'u' prefix
      expect(proof.proofValue, startsWith('u'));

      // Verify the credential
      final verifier = DataIntegrityEddsaJcsVerifier(
        verifierDid: doc.id,
      );
      final result = await verifier.verify(credentialWithProof);

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });

    test('Support both base58 and base64url in same verification flow',
        () async {
      // Create test wallet and generate key
      final seed = Uint8List.fromList(List.generate(32, (index) => index + 5));
      final wallet = Bip32Ed25519Wallet.fromSeed(seed);
      final keyPair = await wallet.generateKey(keyId: "m/0'/0'");
      final doc = DidKey.generateDocument(keyPair.publicKey);

      final credential = MutableVcDataModelV2(
        context: [
          'https://www.w3.org/ns/credentials/v2',
        ],
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

      // Generate with base58 (z prefix)
      final generatorBase58 = DataIntegrityEddsaJcsGenerator(
        signer: signer,
        proofValueMultiBase: MultiBase.base58bitcoin,
      );
      final proofBase58 = await generatorBase58.generate(credential.toJson());

      // Generate with base64url (u prefix)
      final generatorBase64 = DataIntegrityEddsaJcsGenerator(
        signer: signer,
        proofValueMultiBase: MultiBase.base64UrlNoPad,
      );
      final proofBase64 = await generatorBase64.generate(credential.toJson());

      // Verify both encodings work
      expect(proofBase58.proofValue, startsWith('z'));
      expect(proofBase64.proofValue, startsWith('u'));

      // Create verifier (same for both)
      final verifier = DataIntegrityEddsaJcsVerifier(
        verifierDid: doc.id,
      );

      // Verify base58 encoded credential
      final credentialWithProofBase58 = credential.toJson();
      credentialWithProofBase58['proof'] = proofBase58.toJson();
      final resultBase58 = await verifier.verify(credentialWithProofBase58);
      expect(resultBase58.isValid, true);

      // Verify base64url encoded credential
      final credentialWithProofBase64 = credential.toJson();
      credentialWithProofBase64['proof'] = proofBase64.toJson();
      final resultBase64 = await verifier.verify(credentialWithProofBase64);
      expect(resultBase64.isValid, true);
    });
  });
}
