import 'dart:convert';

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
      final verifier = DataIntegrityEcdsaJcsVerifier(issuerDid: issuerDid);

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
      final verifier = DataIntegrityEddsaJcsVerifier(issuerDid: issuerDid);

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
      final verifier = DataIntegrityEcdsaJcsVerifier(issuerDid: issuerDid);

      // Should throw SsiException for invalid encoding
      expect(() => verifier.verify(json), throwsA(isA<SsiException>()));
    });
  });
}
