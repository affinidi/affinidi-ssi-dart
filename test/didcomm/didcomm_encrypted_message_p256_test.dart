import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

import '../fixtures/didcomm_message_fixtures.dart';

void main() {
  group('DIDComm message encryption / decryption (P256)', () {
    late GenericWallet aliceWallet;
    late GenericWallet bobWallet;
    late GenericWallet eveWallet;

    late KeyPair aliceKeyPair;
    late KeyPair bobKeyPair;
    late KeyPair eveKeyPair;

    late DidcommPlaintextMessage message;
    late DidDocument aliceDidDoc;
    late DidDocument bobDidDoc;

    late PublicKey alicePublicKey;
    late PublicKey bobPublicKey;

    late List<Map<String, String>> bobKeyAgreements;

    setUp(() async {
      aliceWallet = GenericWallet(InMemoryKeyStore());
      bobWallet = GenericWallet(InMemoryKeyStore());
      eveWallet = GenericWallet(InMemoryKeyStore());

      aliceKeyPair = await aliceWallet.generateKey(keyType: KeyType.p256);
      bobKeyPair = await bobWallet.generateKey(keyType: KeyType.p256);
      eveKeyPair = await eveWallet.generateKey(keyType: KeyType.p256);

      alicePublicKey = await aliceWallet.getPublicKey(aliceKeyPair.id);
      bobPublicKey = await bobWallet.getPublicKey(bobKeyPair.id);

      aliceDidDoc = DidKey.generateDocument(alicePublicKey);
      bobDidDoc = DidKey.generateDocument(bobPublicKey);

      bobKeyAgreements = bobDidDoc
          .resolveKeyIds()
          .keyAgreement
          .map((ka) => (ka as VerificationMethod).asJwk().toJson())
          .toList();
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
        expect(aHeader['epk']['crv'], equals('P-256'));
        expect(aHeader['epk']['kty'], equals('EC'));
        expect(aHeader['epk']['x'], isNotNull);
        expect(aHeader['epk']['y'], isNotNull);

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
        expect(aHeader['epk']['crv'], equals('P-256'));
        expect(aHeader['epk']['kty'], equals('EC'));
        expect(aHeader['epk']['x'], isNotNull);
        expect(aHeader['epk']['y'], isNotNull);

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
