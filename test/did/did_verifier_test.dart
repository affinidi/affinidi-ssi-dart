import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/did/did_verifier.dart';
import 'package:ssi/src/types.dart';
import 'package:test/test.dart';

void main() {
  group('DidVerifier', () {
    final didKey = 'did:key:z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu';
    final kid = 'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu';

    test('should correctly handle algorithm support for Ed25519 keys',
        () async {
      final verifier = await DidVerifier.create(
        algorithm: SignatureScheme.ed25519,
        kid: kid,
        issuerDid: didKey,
      );

      expect(verifier.isAllowedAlgorithm('EdDSA'), isTrue);
      expect(verifier.isAllowedAlgorithm('Ed25519'), isTrue);
      expect(verifier.isAllowedAlgorithm('ES256K'), isFalse);
      expect(verifier.isAllowedAlgorithm('RS256'), isFalse);
    });

    test('should reject invalid signatures for Ed25519 keys', () async {
      final verifier = await DidVerifier.create(
        algorithm: SignatureScheme.ed25519,
        kid: kid,
        issuerDid: didKey,
      );

      final testData = Uint8List.fromList(utf8.encode('Test data'));
      final fakeSignature = Uint8List.fromList(List.filled(64, 0));

      expect(verifier.verify(testData, fakeSignature), isFalse,
          reason: 'Should reject an obviously fake signature');

      final anotherFakeSignature = Uint8List.fromList(List.filled(64, 1));
      expect(verifier.verify(testData, anotherFakeSignature), isFalse,
          reason: 'Should reject another fake signature');
    });

    test('should handle algorithm mismatches correctly', () async {
      //FIXME should fail here as the resolved key does not match the required algorithm
      //seems that we should discover alogorithm from the verification method
      final wrongAlgVerifier = await DidVerifier.create(
        algorithm: SignatureScheme.ecdsa_p256_sha256,
        kid: kid,
        issuerDid: didKey,
      );

      final testData = Uint8List.fromList(utf8.encode('Test data'));
      final signature = Uint8List.fromList(List.filled(64, 0));

      expect(wrongAlgVerifier.verify(testData, signature), isFalse);
      expect(wrongAlgVerifier.isAllowedAlgorithm('EdDSA'), isFalse);
      expect(wrongAlgVerifier.isAllowedAlgorithm('ES256K'), isFalse);
      expect(wrongAlgVerifier.isAllowedAlgorithm('ES256'), isTrue);
    });
  });
}
