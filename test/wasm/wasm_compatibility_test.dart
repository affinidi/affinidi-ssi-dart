import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('When running supported SSI operations in WebAssembly', () {
    test('it creates a DID and performs cryptographic operations', () async {
      final keyPair = Secp256k1KeyPair.fromSeed(
        Uint8List.fromList(List<int>.generate(32, (index) => index + 1)),
      );
      final payload = Uint8List.fromList([1, 2, 3, 4]);

      final didDocument = DidKey.generateDocument(keyPair.publicKey);
      final signature = await keyPair.sign(payload);
      final encrypted = await keyPair.encrypt(payload);

      expect(didDocument.id.toString(), startsWith('did:key:'));
      expect(await keyPair.verify(payload, signature), isTrue);
      expect(await keyPair.decrypt(encrypted), payload);
    });
  });
}
