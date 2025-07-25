import 'dart:convert';
import 'dart:io';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('Digital Bazaar JCS Test Vectors', () {
    test('Verify ecdsa-jcs-2019 test vector', () async {
      // Load test vector
      final file = File('test/jcs/ecdsa-jcs-2019-digital-bazaar.json');
      final json = jsonDecode(await file.readAsString());

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

      // Extract issuer DID
      final issuerDid = json['issuer'] as String;

      // Create verifier
      final verifier = DataIntegrityEddsaJcsVerifier(issuerDid: issuerDid);

      // Verify the credential
      final result = await verifier.verify(json);

      expect(result.isValid, true);
      expect(result.errors, isEmpty);
    });
  });
}
