import 'dart:typed_data';

import 'package:ssi/src/didcomm/didcomm_encrypted_message.dart';
import 'package:ssi/src/didcomm/didcomm_plaintext_message.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DIDComm message encryption / decryption (secp256k1)', () {
    late Bip32Ed25519Wallet aliceWallet;
    late Bip32Ed25519Wallet bobWallet;
    late Bip32Ed25519Wallet eveWallet;

    late DidcommPlaintextMessage message;
    late DidDocument aliceDidDoc;
    late DidDocument bobDidDoc;

    const aliceKeyId = '1234-0';
    const bobKeyId = '2345-0';
    const eveKeyId = '3456-0';

    late PublicKey alicePublicKey;
    late PublicKey bobPublicKey;

    generateSeed() =>
        Uint8List.fromList(List.generate(32, (index) => index + 1));

    setUp(() async {
      aliceWallet = await Bip32Ed25519Wallet.fromSeed(generateSeed());
      bobWallet = await Bip32Ed25519Wallet.fromSeed(generateSeed());
      eveWallet = await Bip32Ed25519Wallet.fromSeed(generateSeed());

      await aliceWallet.generateKey(
          keyId: aliceKeyId, keyType: KeyType.ed25519);
      await bobWallet.generateKey(keyId: bobKeyId, keyType: KeyType.ed25519);
      await eveWallet.generateKey(keyId: eveKeyId, keyType: KeyType.ed25519);

      alicePublicKey = await aliceWallet.getPublicKey(aliceKeyId);
      bobPublicKey = await bobWallet.getPublicKey(bobKeyId);

      aliceDidDoc = DidKey.generateDocument(alicePublicKey);
      bobDidDoc = DidKey.generateDocument(bobPublicKey);

      message = DidcommPlaintextMessage(
        id: '2fb19055-581d-488e-b357-9d026bee98fc',
        to: [bobDidDoc.id],
        from: aliceDidDoc.id,
        type: 'type',
        body: {"foo": 'bar'},
      );
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      // Get keys from respective wallets
      List<Map<String, String>> bobKeyAgreements = bobDidDoc
          .resolveKeyIds()
          .keyAgreement
          .map((ka) => (ka as VerificationMethod).asJwk().toJson())
          .toList();

      final encryptedFromPlaintext = await message.encrypt(
          wallet: aliceWallet,
          keyId: alicePublicKey.id,
          recipientPublicKeyJwk: bobKeyAgreements);

      final actual = await encryptedFromPlaintext.decrypt(
          wallet: bobWallet, keyId: bobPublicKey.id);

      expect(message.toJson(), actual.toJson());
    });

    test(
        'Two-party encrypt/decrypt including json encoding / decoding should succeed',
        () async {
      List<Map<String, String>> bobKeyAgreements = bobDidDoc
          .resolveKeyIds()
          .keyAgreement
          .map((ka) => (ka as VerificationMethod).asJwk().toJson())
          .toList();

      final encryptedFromPlaintext = await message.encrypt(
          wallet: aliceWallet,
          keyId: alicePublicKey.id,
          recipientPublicKeyJwk: bobKeyAgreements);

      final newMessage =
          DidcommEncryptedMessage.fromJson(encryptedFromPlaintext.toJson());

      final actual =
          await newMessage.decrypt(wallet: bobWallet, keyId: bobPublicKey.id);

      expect(message.toJson(), actual.toJson());
    });

    test('Third party fails to decrypt', () async {
      final evePublicKey = await eveWallet.getPublicKey(eveKeyId);

      List<Map<String, String>> bobKeyAgreements = bobDidDoc
          .resolveKeyIds()
          .keyAgreement
          .map((ka) => (ka as VerificationMethod).asJwk().toJson())
          .toList();

      final encryptedFromPlaintext = await message.encrypt(
          wallet: aliceWallet,
          keyId: alicePublicKey.id,
          recipientPublicKeyJwk: bobKeyAgreements);

      expect(
          () => encryptedFromPlaintext.decrypt(
              wallet: eveWallet, keyId: evePublicKey.id),
          throwsException);
    });
  });
}
