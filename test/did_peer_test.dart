import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:affinidi_ssi/affinidi_ssi.dart';
import 'package:test/test.dart';

void main() {
  final seed = hexDecode(
    // 'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
    'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
  );

  final accountNumber = 24567;

  group('Test DID', () {
    test('the main did peer should match to the expected value', () async {
      final expectedDid =
          'did:peer:0z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy';
      final expectedKeyType = KeyType.ed25519;

      final wallet = await Bip32Ed25519Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final didPeer = await DidPeer.create([keyPair]);
      final actualDid = await didPeer.getDid();
      final actualKeyType = await keyPair.getKeyType();

      expect(actualDid, expectedDid);
      expect(actualKeyType, expectedKeyType);
    });

    test('a derived did keys should start with did:peer:2.Ez6Mk', () async {
      final expectedDidPeerPrefix = 'did:peer:2.Ez6Mk';

      final wallet = await Bip32Ed25519Wallet.fromSeed(seed);
      final derivedKeyId = "$accountNumber-0";
      final keyPair = await wallet.createKeyPair(derivedKeyId);
      final didPeer = await DidPeer.create([keyPair, keyPair], 'https://denys.com/income');
      final actualDid = await didPeer.getDid();

      expect(actualDid, startsWith(expectedDidPeerPrefix));
    });

    test('public key derived from did should be the same', () async {
      final expectedPublicKey = Uint8List.fromList([
        143,
        233,
        105,
        63,
        143,
        166,
        42,
        67,
        5,
        161,
        64,
        185,
        118,
        76,
        94,
        224,
        30,
        69,
        89,
        99,
        116,
        79,
        225,
        130,
        4,
        180,
        251,
        148,
        130,
        73,
        48,
        138
      ]);

      final wallet = await Bip32Ed25519Wallet.fromSeed(seed);
      final rootKeyId = "0-0";
      final keyPair = await wallet.getKeyPair(rootKeyId);
      final didPeer = await DidPeer.create([keyPair]);
      final actualPublicKey = await didPeer.getPublicKey();

      expect(actualPublicKey, expectedPublicKey);
    });
  });
}
