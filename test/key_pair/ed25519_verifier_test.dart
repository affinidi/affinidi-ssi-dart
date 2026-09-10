import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/src/key_pair/ed25519_verifier.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = Uint8List.fromList(List.generate(32, (index) => index + 1));
  final data = Uint8List.fromList([1, 2, 3]);

  // Canonical compressed encodings of the 8 edwards25519 torsion-subgroup
  // points, cross-checked against the libsodium/ref10 low-order blacklist
  // and its canonical sign variants.
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

  group('When verifying an Ed25519 signature', () {
    test('it accepts a valid signature from a real key pair', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      expect(
        verifyEd25519Signature(keyPair.publicKey.bytes, data, signature),
        isTrue,
      );
    });

    test('it rejects a small-order public key', () async {
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

    test('it rejects a small-order signature R component', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      for (final pointHex in smallOrderPointsHex) {
        final forgedSignature = Uint8List.fromList([
          ...hexDecode(pointHex),
          ...signature.sublist(32),
        ]);
        expect(
          verifyEd25519Signature(
            keyPair.publicKey.bytes,
            data,
            forgedSignature,
          ),
          isFalse,
          reason: 'small-order R value $pointHex was accepted',
        );
      }
    });

    test('it rejects a public key whose encoded y is at least p', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      // y == p (2^255 - 19) is a non-canonical encoding of the field
      // element 0; canonical field elements must be strictly less than p.
      final nonCanonicalKey = hexDecode(
        'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      );

      expect(verifyEd25519Signature(nonCanonicalKey, data, signature), isFalse);
    });

    test('it rejects an invalid public key length', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final signature = await keyPair.sign(data);

      expect(verifyEd25519Signature(Uint8List(31), data, signature), isFalse);
    });

    test('it rejects an invalid signature length', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);

      expect(
        verifyEd25519Signature(keyPair.publicKey.bytes, data, Uint8List(63)),
        isFalse,
      );
    });

    test('it accepts RFC 8032 section 7.1 test 1', () {
      final publicKey = hexDecode(
        'd75a980182b10ab7d54bfed3c964073a'
        '0ee172f3daa62325af021a68f707511a',
      );
      final signature = hexDecode(
        'e5564300c360ac729086e2cc806e828a'
        '84877f1eb8e5d974d873e06522490155'
        '5fb8821590a33bacc61e39701cf9b46b'
        'd25bf5f0595bbe24655141438e7a100b',
      );

      expect(
        verifyEd25519Signature(publicKey, Uint8List(0), signature),
        isTrue,
      );
    });

    // C2SP/Wycheproof ed25519_test.json, google-wycheproof v0.9rc5.
    test('it rejects test case 63 where S is replaced by S plus L', () {
      final publicKey = hexDecode(
        '7d4d0e7f6153a69b6242b522abbee685'
        'fda4420f8834b108c3bdae369ef549fa',
      );
      final signature = hexDecode(
        '7c38e026f29e14aabd059a0f2db8b0cd'
        '783040609a8be684db12f82a27774ab0'
        '67654bce3832c2d76f8f6f5dafc08d93'
        '39d4eef676573336a5c51eb6f946b31d',
      );

      expect(
        verifyEd25519Signature(publicKey, hexDecode('54657374'), signature),
        isFalse,
      );
    });

    test('it rejects test case 85 where S is just above L', () {
      final publicKey = hexDecode(
        '100fdf47fb94f1536a4f7c3fda27383f'
        'a03375a8f527c537e6f1703c47f94f86',
      );
      final signature = hexDecode(
        '0971f86d2c9c78582524a103cb9cf949'
        '522ae58f8054dc20107d999be673ff4e'
        '25ebf2f2928766b1248bec6e91697775'
        'f8446639ede46ad4df4053000000010',
      );

      expect(
        verifyEd25519Signature(
          publicKey,
          hexDecode(
            '6a0bc2b0057cedfc0fa2e3f7f7d39279'
            'b30f454a69dfd1117c758d86b19d85e0',
          ),
          signature,
        ),
        isFalse,
      );
    });

    test('it rejects test case 151 where x is zero with its sign bit set', () {
      final publicKey = hexDecode(
        'd75a980182b10ab7d54bfed3c964073a'
        '0ee172f3daa62325af021a68f707511a',
      );
      final signature = hexDecode(
        '01000000000000000000000000000000'
        '00000000000000000000000000000080'
        'c803ee1f2342aa96ff698a393d1ab5e6'
        '6f3eda101d6d120b394c3fd32c117d0a',
      );

      expect(
        verifyEd25519Signature(publicKey, hexDecode('313233343030'), signature),
        isFalse,
      );
    });
  });
}
