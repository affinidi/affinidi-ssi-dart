import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

final _seed = Uint8List.fromList(
  List<int>.generate(32, (index) => index + 1),
);
final _payload = Uint8List.fromList([1, 2, 3, 4]);

void main() {
  group('When running supported SSI operations in WebAssembly', () {
    test('it creates a DID and performs cryptographic operations', () async {
      final keyPair = Secp256k1KeyPair.fromSeed(_seed);

      final didDocument = DidKey.generateDocument(keyPair.publicKey);
      final signature = await keyPair.sign(_payload);
      final encrypted = await keyPair.encrypt(_payload);

      expect(didDocument.id.toString(), startsWith('did:key:'));
      expect(await keyPair.verify(_payload, signature), isTrue);
      expect(await keyPair.decrypt(encrypted), _payload);
    });

    final keyPairs = <String, Future<KeyPair> Function()>{
      'secp256k1': () async => Secp256k1KeyPair.fromSeed(_seed),
      'P-256': () async => P256KeyPair.fromSeed(_seed),
      'P-384': () async => P384KeyPair.fromSeed(_seed),
      'P-521': () async => P521KeyPair.generate().$1,
      'ML-DSA-44': () async => (await MlDsa44KeyPair.fromSeed(_seed)).$1,
    };

    for (final MapEntry(key: algorithm, value: createKeyPair)
        in keyPairs.entries) {
      test('it signs and verifies with $algorithm', () async {
        final keyPair = await createKeyPair();
        final signature = await keyPair.sign(_payload);

        expect(await keyPair.verify(_payload, signature), isTrue);
      });
    }

    final generatedKeyPairs = <String, KeyPair Function()>{
      'secp256k1': () => Secp256k1KeyPair.generate().$1,
      'P-256': () => P256KeyPair.generate().$1,
      'P-384': () => P384KeyPair.generate().$1,
      'P-521': () => P521KeyPair.generate().$1,
      'ML-DSA-44': () => MlDsa44KeyPair.generate().$1,
    };

    for (final MapEntry(key: algorithm, value: generateKeyPair)
        in generatedKeyPairs.entries) {
      test('it securely generates a key pair for $algorithm', () {
        expect(generateKeyPair().publicKey.bytes, isNotEmpty);
      });
    }

    for (final MapEntry(key: algorithm, value: generateKeyPair)
        in generatedKeyPairs.entries.where(
      (entry) => entry.key != 'ML-DSA-44',
    )) {
      test('it encrypts and decrypts with $algorithm', () async {
        final keyPair = generateKeyPair();

        final encrypted = await keyPair.encrypt(_payload);

        expect(await keyPair.decrypt(encrypted), _payload);
      });
    }

    test('it explicitly rejects encryption with ML-DSA-44', () {
      final keyPair = MlDsa44KeyPair.generate().$1;

      expect(
        () => keyPair.encrypt(_payload),
        throwsA(isA<SsiException>()),
      );
    });
  });
}
