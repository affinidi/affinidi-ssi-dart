import 'dart:math';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  // Generate a random 32-byte seed for Ed25519
  final random = Random.secure();
  final seed =
      Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));

  final dataToSign = Uint8List.fromList([1, 2, 3]);

  group('Test Ed25519 Key Pair', () {
    test('it matches the RFC 8032 empty-message signature vector', () async {
      final keyPair = Ed25519KeyPair.fromSeed(
        _decodeHex(
          '9d61b19deffd5a60ba844af492ec2cc4'
          '4449c5697b326919703bac031cae7f60',
        ),
      );

      expect(
        keyPair.publicKey.bytes,
        _decodeHex(
          'd75a980182b10ab7d54bfed3c964073a'
          '0ee172f3daa62325af021a68f707511a',
        ),
      );
      expect(
        await keyPair.sign(Uint8List(0)),
        _decodeHex(
          'e5564300c360ac729086e2cc806e828a'
          '84877f1eb8e5d974d873e06522490155'
          '5fb8821590a33bacc61e39701cf9b46b'
          'd25bf5f0595bbe24655141438e7a100b',
        ),
      );
    });

    test('Ed25519 key pair should sign data and verify signature (default)',
        () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign);
      final actual = await edKey.verify(dataToSign, signature);
      expect(actual, isTrue);
    });

    test('Ed25519 key pair should sign data and verify signature', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign,
          signatureScheme: SignatureScheme.ed25519);
      final actual = await edKey.verify(dataToSign, signature,
          signatureScheme: SignatureScheme.ed25519);
      expect(actual, isTrue);
    });

    test('Verification should fail if signature is invalid (default)',
        () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign);

      // Tamper with the signature
      final invalidSignature = Uint8List.fromList(signature);
      invalidSignature[0] =
          invalidSignature[0] ^ 0xFF; // Flip bits in the first byte

      final actual = await edKey.verify(dataToSign, invalidSignature);
      expect(actual, isFalse);
    });

    test('Verification should fail if data is different (default)', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign);

      final differentData = Uint8List.fromList([3, 2, 1]);

      final actual = await edKey.verify(differentData, signature);
      expect(actual, isFalse);
    });

    test('it rejects a signature with a non-canonical scalar', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final signature = await edKey.sign(dataToSign);
      final nonCanonicalSignature = _addGroupOrderToScalar(signature);

      expect(await edKey.verify(dataToSign, nonCanonicalSignature), isFalse);
    });

    test('Verification works across different supported schemes', () async {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final sigSha = await edKey.sign(dataToSign,
          signatureScheme: SignatureScheme.ed25519);

      expect(
          await edKey.verify(dataToSign, sigSha,
              signatureScheme: SignatureScheme.ed25519),
          isTrue);
    });

    test('Ed25519 key pair properties should be correct', () {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final publicKey = edKey.publicKey;

      expect(publicKey.type, KeyType.ed25519);
      expect(publicKey.bytes.length, 32); // Ed25519 public key length

      // Verify getSeed returns the original seed
      expect(edKey.getSeed(), equals(seed));
    });

    test('KeyPair ID should match PublicKey ID', () {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final publicKey = keyPair.publicKey;
      expect(keyPair.id, equals(publicKey.id));
    });

    test('it generates a 32-byte ephemeral X25519 public key', () {
      final keyPair = Ed25519KeyPair.fromSeed(seed);
      final ephemeralPublicKey = keyPair.generateEphemeralPubKey();

      expect(ephemeralPublicKey, isA<Uint8List>());
      expect(ephemeralPublicKey, hasLength(32));
    });

    test('it rejects an X25519 public key that is not 32 bytes', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);

      await expectLater(
        keyPair.computeEcdhSecret(Uint8List(33)),
        throwsA(
          isA<ArgumentError>().having(
            (error) => error.message,
            'message',
            'bad scalar length: 33, expected 32',
          ),
        ),
      );
    });

    test('it rejects all known low-order X25519 public keys', () async {
      final keyPair = Ed25519KeyPair.fromSeed(seed);

      const lowOrderPublicKeys = [
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0100000000000000000000000000000000000000000000000000000000000000',
        'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
        '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      ];

      for (final publicKey in lowOrderPublicKeys) {
        await expectLater(
          keyPair.computeEcdhSecret(_decodeHex(publicKey)),
          throwsA(
            isA<ArgumentError>().having(
              (error) => error.message,
              'message',
              'bad input point: low order point',
            ),
          ),
          reason: 'low-order public key $publicKey was accepted',
        );
      }
    });

    test('supportedSignatureSchemes should return correct schemes', () {
      final edKey = Ed25519KeyPair.fromSeed(seed);
      final schemes = edKey.supportedSignatureSchemes;
      expect(schemes, hasLength(1));
      expect(schemes, contains(SignatureScheme.ed25519));
    });
  });
}

Uint8List _decodeHex(String value) => Uint8List.fromList([
      for (var offset = 0; offset < value.length; offset += 2)
        int.parse(value.substring(offset, offset + 2), radix: 16),
    ]);

Uint8List _addGroupOrderToScalar(Uint8List signature) {
  const groupOrder = <int>[
    0xed,
    0xd3,
    0xf5,
    0x5c,
    0x1a,
    0x63,
    0x12,
    0x58,
    0xd6,
    0x9c,
    0xf7,
    0xa2,
    0xde,
    0xf9,
    0xde,
    0x14,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x10,
  ];
  final result = Uint8List.fromList(signature);
  var carry = 0;
  for (var index = 0; index < groupOrder.length; index++) {
    final sum = result[index + 32] + groupOrder[index] + carry;
    result[index + 32] = sum & 0xff;
    carry = sum >> 8;
  }
  return result;
}
