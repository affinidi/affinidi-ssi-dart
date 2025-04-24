import 'package:ssi/src/didcomm/didcomm_plaintext_message.dart';
import 'package:ssi/src/didcomm/didcomm_signed_message.dart';
import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';
import 'package:test/test.dart';

void main() {
  group('DIDComm message signing / verifying (P256)', () {
    late GenericWallet aliceWallet;
    late GenericWallet bobWallet;
    late DidcommPlaintextMessage message;

    late PublicKey alicePublicKey;
    late DidDocument aliceDidDoc;

    setUp(() async {
      KeyStore aliceKeyStore = InMemoryKeyStore();
      aliceWallet = GenericWallet(aliceKeyStore);

      KeyStore bobKeyStore = InMemoryKeyStore();
      bobWallet = GenericWallet(bobKeyStore);

      alicePublicKey = await aliceWallet.generateKey(keyType: KeyType.p256);
      aliceDidDoc = DidKey.generateDocument(alicePublicKey);

      message = DidcommPlaintextMessage(
        id: '2fb19055-581d-488e-b357-9d026bee98fc',
        to: ['did:key:123456'],
        from: aliceDidDoc.id,
        type: 'type',
        body: {"foo": 'bar'},
      );
    });

    test('Sign & verify message', () async {
      DidcommSignedMessage signedMessage =
          await message.sign(wallet: aliceWallet, keyId: alicePublicKey.id);

      // TODO: improve interface and take multiple key agreements into account?
      bool actual = await signedMessage
          .verify(aliceDidDoc.resolveKeyIds().keyAgreement[0].asJwk());

      expect(signedMessage.payload, message);
      expect(actual, true);
    });

    test('verification fails', () async {
      DidcommSignedMessage signedMessage =
          await message.sign(wallet: aliceWallet, keyId: alicePublicKey.id);

      PublicKey bobPublicKey = await bobWallet.generateKey();
      DidDocument bobDidDoc = DidKey.generateDocument(bobPublicKey);

      expect(
          () => signedMessage
              .verify(bobDidDoc.resolveKeyIds().keyAgreement[0].asJwk()),
          throwsException);
    });
  });
}
