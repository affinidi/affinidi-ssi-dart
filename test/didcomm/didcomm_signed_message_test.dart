import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DIDComm message signing / verifying (P256)', () {
    late GenericWallet aliceWallet;
    late GenericWallet bobWallet;
    late DidcommPlaintextMessage message;

    late KeyPair aliceKeyPair;
    late DidDocument aliceDidDoc;

    late DidSigner aliceSigner;

    setUp(() async {
      KeyStore aliceKeyStore = InMemoryKeyStore();
      aliceWallet = GenericWallet(aliceKeyStore);

      KeyStore bobKeyStore = InMemoryKeyStore();
      bobWallet = GenericWallet(bobKeyStore);

      aliceKeyPair = await aliceWallet.generateKey(keyType: KeyType.p256);
      aliceDidDoc = DidKey.generateDocument(aliceKeyPair.publicKey);

      message = DidcommPlaintextMessage(
        id: '2fb19055-581d-488e-b357-9d026bee98fc',
        to: ['did:key:123456'],
        from: aliceDidDoc.id,
        type: 'type',
        body: {"foo": 'bar'},
      );

      aliceSigner = DidSigner(
        didDocument: aliceDidDoc,
        keyPair: aliceKeyPair,
        didKeyId: aliceDidDoc.verificationMethod[0].id,
        signatureScheme: SignatureScheme.ecdsa_p256_sha256,
      );
    });

    test('Sign & verify message', () async {
      DidcommSignedMessage signedMessage = await message.sign(aliceSigner);

      // TODO: improve interface and take multiple key agreements into account?
      bool actual = await signedMessage
          .verify(aliceDidDoc.resolveKeyIds().keyAgreement[0].asJwk());

      expect(signedMessage.payload, message);
      expect(actual, true);
    });

    test('set plaintext message sender (from) when signing', () async {
      DidcommPlaintextMessage messageWithoutSender = DidcommPlaintextMessage.to(
          'did:key:123456',
          type: 'type',
          body: {"foo": 'bar'});

      final foobar = await messageWithoutSender.sign(aliceSigner);

      expect(messageWithoutSender.from, aliceSigner.did);
      expect(foobar.payload.toJson()['from'], aliceSigner.did);
    });

    test('do not overwrite sender (from) value if already set', () async {
      String from = 'did:key:99999';
      DidcommPlaintextMessage messageWithSender = DidcommPlaintextMessage(
        id: '2fb19055-581d-488e-b357-9d026bee98fc',
        to: ['did:key:123456'],
        from: from,
        type: 'type',
        body: {"foo": 'bar'},
      );

      final actual = await messageWithSender.sign(aliceSigner);
      expect(actual.payload.toJson()['from'], from);
      expect(messageWithSender.from, from);
    });

    test('verification fails', () async {
      DidcommSignedMessage signedMessage = await message.sign(aliceSigner);

      KeyPair bobKeyPair = await bobWallet.generateKey();
      DidDocument bobDidDoc = DidKey.generateDocument(bobKeyPair.publicKey);

      expect(
          () => signedMessage
              .verify(bobDidDoc.resolveKeyIds().keyAgreement[0].asJwk()),
          throwsException);
    });

    test('Signed message instance stores every signature internally', () async {
      DidcommSignedMessage signedMessage = await message.sign(aliceSigner);
      expect(signedMessage.signatures!.length, 1);

      await signedMessage.sign(aliceSigner);
      expect(signedMessage.signatures!.length, 2);
    });
  });
}
