import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:affinidi_ssi/affinidi_ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  final accountNumber = 24567;

  group('Test DID', () {
    test('the main did key should match to the expected value', () async {
      final expectedDid =
          'did:key:zQ3shd83o9cAdtd5SFF8epKAqDBpMV3x9f3sbv4mMPV8uaDC2';
      final expectedKeyType = KeyType.secp256k1;

      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final didKey = await DidKey.create([keyPair]);
      final actualDid = await didKey.getDid();
      final actualKeyType = await keyPair.getKeyType();

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('a derived did keys should start with did:key:zQ3s', () async {
      final expectedDidKeyPrefix = 'did:key:zQ3s';

      final wallet = Bip32Wallet.fromSeed(seed);
      final derivedKeyId = "$accountNumber-0";
      final keyPair = await wallet.createKeyPair(derivedKeyId);
      final didKey = await DidKey.create([keyPair]);
      final actualDid = await didKey.getDid();

      expect(actualDid, startsWith(expectedDidKeyPrefix));
    });

    test('did should be different if the wrong key type is provided', () async {
      final expectedDid =
          'did:key:zQ3shvpfWjYk7DfbsyAEFQTfmz3qjeDmdNcJ8a1mhkps4qKGj';
      final expectedKeyType = KeyType.secp256k1;

      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final didKey = await DidKey.create([keyPair]);
      final actualDid = await didKey.getDid();
      final actualKeyType = await keyPair.getKeyType();

      expect(actualDid, isNot(equals(expectedDid)));
      expect(actualKeyType, expectedKeyType);
    });

    test('public key derived from did should be the same', () async {
      final expectedPublicKey = Uint8List.fromList([
        2,
        233,
        113,
        31,
        100,
        37,
        199,
        52,
        153,
        50,
        216,
        134,
        234,
        13,
        174,
        130,
        68,
        201,
        134,
        53,
        18,
        63,
        241,
        99,
        53,
        238,
        174,
        142,
        117,
        242,
        57,
        243,
        247
      ]);

      final wallet = Bip32Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final didKey = await DidKey.create([keyPair]);
      final actualPublicKey = await didKey.getPublicKey();

      expect(actualPublicKey, expectedPublicKey);
    });
  });
}
