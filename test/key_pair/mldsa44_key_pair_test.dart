import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('MlDsa44KeyPair', () {
    group('generate', () {
      test('generates a fresh key pair with correct sizes', () {
        final (kp, keyBlob) = MlDsa44KeyPair.generate();
        expect(kp.publicKey.bytes.length, 1312,
            reason: 'ML-DSA-44 public key must be 1312 bytes');
        expect(keyBlob.length, 3872,
            reason: 'key blob (sk||pk) must be 2560+1312=3872 bytes');
        expect(kp.publicKey.type, KeyType.mldsa44);
      });

      test('two generated key pairs are distinct', () {
        final (kp1, _) = MlDsa44KeyPair.generate();
        final (kp2, _) = MlDsa44KeyPair.generate();
        expect(kp1.publicKey.bytes, isNot(equals(kp2.publicKey.bytes)));
      });

      test('uses provided key ID', () {
        final (kp, _) = MlDsa44KeyPair.generate(id: 'my-key');
        expect(kp.id, 'my-key');
        expect(kp.publicKey.id, 'my-key');
      });
    });

    group('fromPrivateKey', () {
      test('reconstructs key pair from key blob', () {
        final (original, keyBlob) = MlDsa44KeyPair.generate(id: 'test-key');
        final restored = MlDsa44KeyPair.fromPrivateKey(keyBlob, id: 'test-key');
        expect(restored.publicKey.bytes, equals(original.publicKey.bytes));
        expect(restored.publicKey.type, KeyType.mldsa44);
      });

      test('throws on wrong blob length', () {
        expect(
          () => MlDsa44KeyPair.fromPrivateKey(Uint8List(100)),
          throwsA(isA<SsiException>()),
        );
      });
    });

    group('fromSeed', () {
      test('is deterministic: same seed produces identical key pair', () async {
        final seed = Uint8List.fromList(List.generate(32, (i) => i));
        final (kp1, _) = await MlDsa44KeyPair.fromSeed(seed);
        final (kp2, _) = await MlDsa44KeyPair.fromSeed(seed);
        expect(kp1.publicKey.bytes, equals(kp2.publicKey.bytes));
      });

      test('different seeds produce different key pairs', () async {
        final seed1 = Uint8List.fromList(List.generate(32, (i) => i));
        final seed2 = Uint8List.fromList(List.generate(32, (i) => i + 1));
        final (kp1, _) = await MlDsa44KeyPair.fromSeed(seed1);
        final (kp2, _) = await MlDsa44KeyPair.fromSeed(seed2);
        expect(kp1.publicKey.bytes, isNot(equals(kp2.publicKey.bytes)));
      });

      test('returns a valid key blob for re-creation', () async {
        final seed = Uint8List.fromList(List.generate(32, (i) => i));
        final (kp, keyBlob) = await MlDsa44KeyPair.fromSeed(seed);
        expect(keyBlob.length, 3872);
        final restored = MlDsa44KeyPair.fromPrivateKey(keyBlob);
        expect(restored.publicKey.bytes, equals(kp.publicKey.bytes));
      });
    });

    group('sign and verify', () {
      late MlDsa44KeyPair kp;
      setUp(() {
        final (pair, _) = MlDsa44KeyPair.generate();
        kp = pair;
      });

      test('signs and self-verifies', () async {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final sig = await kp.sign(data);
        expect(sig.length, 2420,
            reason: 'ML-DSA-44 signature must be 2420 bytes');
        expect(await kp.verify(data, sig), isTrue);
      });

      test('fails verification on tampered signature', () async {
        final data = Uint8List.fromList([1, 2, 3, 4, 5]);
        final sig = Uint8List.fromList(await kp.sign(data));
        sig[0] ^= 0xFF; // flip bits in first byte
        expect(await kp.verify(data, sig), isFalse);
      });

      test('fails verification on different data', () async {
        final data = Uint8List.fromList([1, 2, 3]);
        final sig = await kp.sign(data);
        expect(await kp.verify(Uint8List.fromList([3, 2, 1]), sig), isFalse);
      });

      test('fails verification with wrong-length signature', () async {
        final data = Uint8List.fromList([1, 2, 3]);
        expect(await kp.verify(data, Uint8List(100)), isFalse);
      });

      test('uses mldsa44 signature scheme', () {
        expect(kp.defaultSignatureScheme, SignatureScheme.mldsa44);
        expect(kp.supportedSignatureSchemes, [SignatureScheme.mldsa44]);
      });
    });

    group('unsupported operations', () {
      late MlDsa44KeyPair kp;
      setUp(() {
        final (pair, _) = MlDsa44KeyPair.generate();
        kp = pair;
      });

      test('encrypt throws SsiException', () {
        expect(
          () => kp.encrypt(Uint8List(8)),
          throwsA(isA<SsiException>()),
        );
      });

      test('decrypt throws SsiException', () {
        expect(
          () => kp.decrypt(Uint8List(8)),
          throwsA(isA<SsiException>()),
        );
      });

      test('computeEcdhSecret throws SsiException', () {
        expect(
          () => kp.computeEcdhSecret(Uint8List(32)),
          throwsA(isA<SsiException>()),
        );
      });
    });

    group('multikey codec', () {
      test('toMultikey prepends 0x90 0x24 prefix', () {
        final (kp, _) = MlDsa44KeyPair.generate();
        final multikey = toMultikey(kp.publicKey.bytes, KeyType.mldsa44);
        expect(multikey.length, 1314, reason: '2 prefix + 1312 key bytes');
        expect(multikey[0], 0x90);
        expect(multikey[1], 0x24);
      });

      test('multibase round-trip', () {
        final (kp, _) = MlDsa44KeyPair.generate();
        final multikey = toMultikey(kp.publicKey.bytes, KeyType.mldsa44);
        final encoded = toMultiBase(multikey, base: MultiBase.base64UrlNoPad);
        final decoded = multiBaseToUint8List(encoded);
        expect(decoded, equals(multikey));
      });
    });
  });
}
