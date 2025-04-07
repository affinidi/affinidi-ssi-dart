import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/src/did/did_verifier.dart';
import 'package:test/test.dart';

void main() {
  group('DidVerifier', () {
    test('flow test for DidVerifier creation and functionality', () async {
      final String didKey =
          'did:key:z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu';

      final kid = 'z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu';

      final DidVerifier verifier = await DidVerifier.create(
        algorithm: 'EdDSA',
        kid: kid,
        issuerDid: didKey,
      );

      expect(verifier.keyId, equals(kid));
      expect(verifier.isAllowedAlgorithm('EdDSA'), isTrue);
      expect(verifier.isAllowedAlgorithm('Ed25519'), isTrue);
      expect(verifier.isAllowedAlgorithm('ES256K'), isFalse);

      final testData = Uint8List.fromList(utf8.encode('Test data'));
      final Uint8List fakeSignature = Uint8List.fromList(List.filled(64, 0));

      final result = verifier.verify(testData, fakeSignature);

      expect(result, isFalse);
    });
  });
}
