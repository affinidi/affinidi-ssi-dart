import 'dart:math';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/didcomm_message_fixtures.dart';

void main() {
  group('DIDComm message encryption / decryption (x22519)', () {
    late Bip32Ed25519Wallet aliceWallet;
    late Bip32Ed25519Wallet bobWallet;
    late Bip32Ed25519Wallet eveWallet;

    late DidcommPlaintextMessage message;
    late DidDocument aliceDidDoc;
    late DidDocument bobDidDoc;

    late KeyPair aliceKeyPair;
    late KeyPair bobKeyPair;
    late KeyPair eveKeyPair;

    late List<Map<String, dynamic>> bobKeyAgreements;

    generateSeed() =>
        Uint8List.fromList(List.generate(32, (index) => Random().nextInt(32)));

    setUp(() async {
      aliceWallet = await Bip32Ed25519Wallet.fromSeed(
        generateSeed(),
        InMemoryKeyStore(),
      );

      bobWallet = await Bip32Ed25519Wallet.fromSeed(
        generateSeed(),
        InMemoryKeyStore(),
      );

      eveWallet = await Bip32Ed25519Wallet.fromSeed(
        generateSeed(),
        InMemoryKeyStore(),
      );

      aliceKeyPair = await aliceWallet.deriveKey(
        derivationPath: "m/44'/60'/0'/0'/0'",
      );

      bobKeyPair = await bobWallet.deriveKey(
        derivationPath: "m/44'/60'/0'/0'/0'",
      );

      final aliceX25519PublicKey =
          await aliceWallet.getX25519PublicKey(aliceKeyPair.id);

      final bobX25519PublicKey =
          await bobWallet.getX25519PublicKey(bobKeyPair.id);

      eveKeyPair = await eveWallet.deriveKey(
          keyType: KeyType.ed25519, derivationPath: "m/44'/60'/0'/0'/0'");

      aliceDidDoc = DidKey.generateDocument(
          PublicKey(aliceKeyPair.id, aliceX25519PublicKey, KeyType.x25519));

      bobDidDoc = DidKey.generateDocument(
          PublicKey(bobKeyPair.id, bobX25519PublicKey, KeyType.x25519));

      message = DidcommPlaintextMessage(
        id: '2fb19055-581d-488e-b357-9d026bee98fc',
        to: [bobDidDoc.id],
        from: aliceDidDoc.id,
        type: 'type',
        body: {"foo": 'bar'},
      );

      bobKeyAgreements = bobDidDoc
          .resolveKeyIds()
          .keyAgreement
          .map((ka) => (ka as VerificationMethod).asJwk().toJson())
          .toList();
    });

    test('Two-party encrypt/decrypt should succeed', () async {
      // Get keys from respective wallets

      final encryptedFromPlaintext = await message.encrypt(
          wallet: aliceWallet,
          keyId: aliceKeyPair.id,
          recipientPublicKeyJwks: bobKeyAgreements);

      final actual = await encryptedFromPlaintext.decrypt(
          wallet: bobWallet, keyId: bobKeyPair.id);

      expect(message.toJson(), actual.toJson());
    });

    group('key wrap algorithm :: ECDH-ES', () {
      test('Two-party encrypt/decrypt should succeed', () async {
        DidcommPlaintextMessage message =
            DidcommMessageFixtures.getMessage(to: bobDidDoc.id);

        DidcommEncryptedMessage encryptedMessage = await message.encrypt(
            keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
            wallet: aliceWallet,
            keyId: aliceKeyPair.id,
            recipientPublicKeyJwks: bobKeyAgreements);

        DidcommMessage actual = await encryptedMessage.decrypt(
            wallet: bobWallet, keyId: bobKeyPair.id);
        expect(actual.toJson(), equals(message.toJson()));
      });

      test('Third party fails to decrypt', () async {
        DidcommPlaintextMessage message =
            DidcommMessageFixtures.getMessage(to: bobDidDoc.id);

        DidcommEncryptedMessage encryptedMessage = await message.encrypt(
            keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
            wallet: aliceWallet,
            keyId: aliceKeyPair.id,
            recipientPublicKeyJwks: bobKeyAgreements);

        expect(
            () => encryptedMessage.decrypt(
                wallet: eveWallet, keyId: eveKeyPair.id),
            throwsException);
      });

      test('should have valid encrypted message', () async {
        DidcommPlaintextMessage message =
            DidcommMessageFixtures.getMessage(to: bobDidDoc.id);

        DidcommEncryptedMessage encryptedMessage = await message.encrypt(
            keyWrapAlgorithm: KeyWrapAlgorithm.ecdhES,
            wallet: aliceWallet,
            keyId: aliceKeyPair.id,
            recipientPublicKeyJwks: bobKeyAgreements);

        Map<String, dynamic> aHeader =
            encryptedMessage.protectedHeader.toJson();

        // check recipients
        expect(encryptedMessage.recipients.length, equals(1));
        expect(encryptedMessage.recipients[0].header.kid,
            equals(bobDidDoc.verificationMethod[0].id));
        expect(encryptedMessage.recipients[0].encryptedKey, isNotNull);

        // check JWE header
        expect(aHeader['skid'], equals(aliceDidDoc.verificationMethod[0].id));
        expect(aHeader['enc'], equals(EncryptionAlgorithm.a256cbc.value));
        expect(aHeader['alg'], equals(KeyWrapAlgorithm.ecdhES.value));
        expect(aHeader['typ'], equals(DidcommMessageTyp.encrypted.value));
        expect(aHeader['apu'], isNull);
        expect(aHeader['apv'], isNotNull);
        expect(aHeader['epk']['crv'], equals('X25519'));
        expect(aHeader['epk']['kty'], equals('OKP'));
        expect(aHeader['epk']['x'], isNotNull);
        expect(aHeader['epk']['y'], isNull);

        // others
        expect(encryptedMessage.ciphertext, isNotNull);
        expect(encryptedMessage.tag, isNotNull);
        expect(encryptedMessage.iv, isNotNull);
      });
    });

    group('key wrap algorithm :: ECDH-1PU+A256KW', () {
      test('Two-party encrypt/decrypt should succeed', () async {
        DidcommPlaintextMessage message = DidcommMessageFixtures.getMessage(
            to: bobDidDoc.id, from: aliceDidDoc.id);

        DidcommEncryptedMessage encryptedMessage = await message.encrypt(
            keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
            wallet: aliceWallet,
            keyId: aliceKeyPair.id,
            recipientPublicKeyJwks: bobKeyAgreements);

        DidcommMessage actual = await encryptedMessage.decrypt(
            wallet: bobWallet, keyId: bobKeyPair.id);
        expect(actual.toJson(), equals(message.toJson()));
      });

      test('Third party fails to decrypt', () async {
        DidcommPlaintextMessage message = DidcommMessageFixtures.getMessage(
            to: bobDidDoc.id, from: aliceDidDoc.id);

        DidcommEncryptedMessage encryptedMessage = await message.encrypt(
            keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
            wallet: aliceWallet,
            keyId: aliceKeyPair.id,
            recipientPublicKeyJwks: bobKeyAgreements);

        expect(
            () => encryptedMessage.decrypt(
                wallet: eveWallet, keyId: eveKeyPair.id),
            throwsException);
      });

      test('should have valid encrypted message', () async {
        DidcommPlaintextMessage message = DidcommMessageFixtures.getMessage(
            to: bobDidDoc.id, from: aliceDidDoc.id);

        DidcommEncryptedMessage encryptedMessage = await message.encrypt(
            keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
            wallet: aliceWallet,
            keyId: aliceKeyPair.id,
            recipientPublicKeyJwks: bobKeyAgreements);

        Map<String, dynamic> aHeader =
            encryptedMessage.protectedHeader.toJson();

        // check recipients
        expect(encryptedMessage.recipients.length, equals(1));
        expect(encryptedMessage.recipients[0].header.kid,
            equals(bobDidDoc.verificationMethod[0].id));
        expect(encryptedMessage.recipients[0].encryptedKey, isNotNull);

        // check JWE header
        expect(aHeader['skid'], equals(aliceDidDoc.verificationMethod[0].id));
        expect(aHeader['enc'], equals(EncryptionAlgorithm.a256cbc.value));
        expect(aHeader['alg'], equals(KeyWrapAlgorithm.ecdh1PU.value));
        expect(aHeader['typ'], equals(DidcommMessageTyp.encrypted.value));
        expect(aHeader['apu'], isNotNull);
        expect(aHeader['apv'], isNotNull);
        expect(aHeader['epk']['crv'], equals('X25519'));
        expect(aHeader['epk']['kty'], equals('OKP'));
        expect(aHeader['epk']['x'], isNotNull);
        expect(aHeader['epk']['y'], isNull);

        // others
        expect(encryptedMessage.ciphertext, isNotNull);
        expect(encryptedMessage.tag, isNotNull);
        expect(encryptedMessage.iv, isNotNull);
      });

      test('should throw exception if message.from is emtpy', () {
        DidcommPlaintextMessage message =
            DidcommMessageFixtures.getMessage(to: bobDidDoc.id);
        expect(
            () => message.encrypt(
                keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
                wallet: aliceWallet,
                keyId: aliceKeyPair.id,
                recipientPublicKeyJwks: bobKeyAgreements),
            throwsA(predicate((e) =>
                e is Exception &&
                (e as dynamic).message ==
                    'For authcrypted messages the from-header of the plaintext message must not be null')));
      });

      test(
          'Two-party encrypt/decrypt should succeed with alternative encryption algorhithm A256GCM',
          () async {
        DidcommPlaintextMessage message = DidcommMessageFixtures.getMessage(
            to: bobDidDoc.id, from: aliceDidDoc.id);

        DidcommEncryptedMessage encryptedMessage = await message.encrypt(
            keyWrapAlgorithm: KeyWrapAlgorithm.ecdh1PU,
            encryptionAlgorithm: EncryptionAlgorithm.a256gcm,
            wallet: aliceWallet,
            keyId: aliceKeyPair.id,
            recipientPublicKeyJwks: bobKeyAgreements);

        DidcommMessage actual = await encryptedMessage.decrypt(
            wallet: bobWallet, keyId: bobKeyPair.id);

        expect(actual.toJson(), equals(message.toJson()));

        Map<String, dynamic> aHeader =
            encryptedMessage.protectedHeader.toJson();
        expect(aHeader['enc'], equals(EncryptionAlgorithm.a256gcm.value));
      });
    });
  });
}
