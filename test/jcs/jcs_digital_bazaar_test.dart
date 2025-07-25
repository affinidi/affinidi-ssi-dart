import 'dart:convert';
import 'dart:io';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('Digital Bazaar JCS Test Vectors', () {
    test('Verify ecdsa-jcs-2019 test vector', () async {
      // Load test vector
      final file = File('test/jcs/ecdsa-jcs-2019-digital-bazaar.json');
      final json = jsonDecode(await file.readAsString());

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
      // Load test vector
      final file = File('test/jcs/eddsa-jcs-2022-digital-bazaar.json');
      final json = jsonDecode(await file.readAsString());

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
      final file = File('test/jcs/ecdsa-jcs-2019-digital-bazaar.json');
      final json = jsonDecode(await file.readAsString());

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
