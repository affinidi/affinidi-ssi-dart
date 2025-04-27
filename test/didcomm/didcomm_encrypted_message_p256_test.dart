import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DIDComm message encryption / decryption (P256)', () {
    late GenericWallet aliceWallet;
    late GenericWallet bobWallet;
    late GenericWallet eveWallet;

    late InMemoryKeyStore aliceKeyStore;
    late InMemoryKeyStore bobKeyStore;
    late InMemoryKeyStore eveKeyStore;

    late DidcommPlaintextMessage message;
    late DidDocument aliceDidDoc;
    late DidDocument bobDidDoc;

    const aliceKeyId = 'alice-p256-key';
    const bobKeyId = 'bob-p256-key';
    const eveKeyId = 'eve-p256-key';

    late PublicKey alicePublicKey;
    late PublicKey bobPublicKey;

    setUp(() async {
      aliceKeyStore = InMemoryKeyStore();
      bobKeyStore = InMemoryKeyStore();
      eveKeyStore = InMemoryKeyStore();

      aliceWallet = GenericWallet(aliceKeyStore);
      bobWallet = GenericWallet(bobKeyStore);
      eveWallet = GenericWallet(eveKeyStore);

      await aliceWallet.generateKey(keyId: aliceKeyId, keyType: KeyType.p256);
      await bobWallet.generateKey(keyId: bobKeyId, keyType: KeyType.p256);
      await eveWallet.generateKey(keyId: eveKeyId, keyType: KeyType.p256);

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
          recipientPublicKeyJwks: bobKeyAgreements);

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
          recipientPublicKeyJwks: bobKeyAgreements);

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
          recipientPublicKeyJwks: bobKeyAgreements);

      expect(
          () => encryptedFromPlaintext.decrypt(
              wallet: eveWallet, keyId: evePublicKey.id),
          throwsException);
    });
  });
}
