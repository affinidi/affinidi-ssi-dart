import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/key_pair/ed25519_verifier.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
  final data = Uint8List.fromList([1, 2, 3]);

  // Canonical compressed encodings of the 8 edwards25519 torsion-subgroup
  // points (order dividing 8, including the identity), independently
  // derived and verified (on-curve, 8P == identity) rather than copied
  // from an external source.
  const smallOrderPointsHex = [
    '0100000000000000000000000000000000000000000000000000000000000000',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    '0000000000000000000000000000000000000000000000000000000000000080',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    '0000000000000000000000000000000000000000000000000000000000000000',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  ];

  group('verifyEd25519Signature', () {
    test('accepts a valid signature from a real key pair', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      expect(
        verifyEd25519Signature(keyPair.publicKey.bytes, data, signature),
        isTrue,
      );
    });

    test('rejects when the public key is a small-order point', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      for (final pointHex in smallOrderPointsHex) {
        final smallOrderKey = hexDecode(pointHex);
        expect(
          verifyEd25519Signature(smallOrderKey, data, signature),
          isFalse,
          reason: 'small-order public key $pointHex was accepted',
        );
      }
    });

    test('rejects when the signature R component is a small-order point',
        () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      for (final pointHex in smallOrderPointsHex) {
        final forgedSignature = Uint8List.fromList([
          ...hexDecode(pointHex),
          ...signature.sublist(32),
        ]);
        expect(
          verifyEd25519Signature(
              keyPair.publicKey.bytes, data, forgedSignature),
          isFalse,
          reason: 'small-order R value $pointHex was accepted',
        );
      }
    });

    test('rejects a non-canonically encoded public key (y >= p)', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      // y == p (2^255 - 19) is a non-canonical encoding of the field
      // element 0; canonical field elements must be strictly less than p.
      final nonCanonicalKey = hexDecode(
        'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      );

      expect(
        verifyEd25519Signature(nonCanonicalKey, data, signature),
        isFalse,
      );
    });

    test('rejects an invalid public key length', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      expect(
        verifyEd25519Signature(Uint8List(31), data, signature),
        isFalse,
      );
    });

    test('rejects an invalid signature length', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);

      expect(
        verifyEd25519Signature(keyPair.publicKey.bytes, data, Uint8List(63)),
        isFalse,
      );
    });
  });
}
