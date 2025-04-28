import 'dart:math';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DIDComm message encryption / decryption (secp256k1)', () {
    late Bip32Wallet aliceWallet;
    late Bip32Wallet bobWallet;
    late Bip32Wallet eveWallet;

    late DidcommPlaintextMessage message;
    late DidDocument aliceDidDoc;
    late DidDocument bobDidDoc;

    const aliceKeyId = '1234-0';
    const bobKeyId = '2345-0';
    const eveKeyId = '3456-0';

    late KeyPair aliceKeyPair;
    late KeyPair bobKeyPair;

    generateSeed() =>
        Uint8List.fromList(List.generate(32, (index) => Random().nextInt(32)));

    setUp(() async {
      aliceWallet =
          await Bip32Wallet.fromSeed(generateSeed(), InMemoryKeyStore());

      bobWallet =
          await Bip32Wallet.fromSeed(generateSeed(), InMemoryKeyStore());

      eveWallet =
          await Bip32Wallet.fromSeed(generateSeed(), InMemoryKeyStore());

      aliceKeyPair = await aliceWallet.deriveKey(
        keyId: aliceKeyId,
        keyType: KeyType.secp256k1,
        derivationPath: "m/44'/60'/0'/0/0",
      );

      bobKeyPair = await bobWallet.deriveKey(
        keyId: bobKeyId,
        keyType: KeyType.secp256k1,
        derivationPath: "m/44'/60'/0'/0/0",
      );

      await eveWallet.deriveKey(
        keyId: eveKeyId,
        keyType: KeyType.secp256k1,
        derivationPath: "m/44'/60'/0'/0/0",
      );

      aliceDidDoc = DidKey.generateDocument(aliceKeyPair.publicKey);
      bobDidDoc = DidKey.generateDocument(bobKeyPair.publicKey);

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
          keyId: aliceKeyPair.id,
          recipientPublicKeyJwks: bobKeyAgreements);

      final actual = await encryptedFromPlaintext.decrypt(
          wallet: bobWallet, keyId: bobKeyPair.id);

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
          keyId: aliceKeyPair.id,
          recipientPublicKeyJwks: bobKeyAgreements);

      final newMessage =
          DidcommEncryptedMessage.fromJson(encryptedFromPlaintext.toJson());

      final actual =
          await newMessage.decrypt(wallet: bobWallet, keyId: bobKeyPair.id);

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
          keyId: aliceKeyPair.id,
          recipientPublicKeyJwks: bobKeyAgreements);

      expect(
          () => encryptedFromPlaintext.decrypt(
              wallet: eveWallet, keyId: evePublicKey.id),
          throwsException);
    });

    // test('decrypt with jwk', () async {
    //   List<Map<String, String>> bobKeyAgreements = bobDidDoc
    //       .resolveKeyIds()
    //       .keyAgreement
    //       .map((ka) => (ka as VerificationMethod).asJwk().toJson())
    //       .toList();

    //   final meetingplace =
    //       await UniversalDIDResolver.resolve('did:web:meetingplace.world');

    //   List<Map<String, String>> meetingPlaceAgreements = meetingplace
    //       .resolveKeyIds()
    //       .keyAgreement
    //       .map((ka) => (ka as VerificationMethod).asJwk().toJson())
    //       .toList();

    //   final encryptedFromPlaintext = await message.encrypt(
    //       wallet: aliceWallet,
    //       keyId: aliceKeyPair.id,
    //       recipientPublicKeyJwks: meetingPlaceAgreements);

    //   print(await encryptedFromPlaintext.decryptWithPrivateJwk(
    //       privateKeyJwk, 'did:web:meetingplace.world'));
    // });
  });
}
