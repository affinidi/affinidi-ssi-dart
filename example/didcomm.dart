import 'package:ssi/src/didcomm/didcomm_encrypted_message.dart';
import 'package:ssi/src/didcomm/didcomm_message.dart';
import 'package:ssi/src/didcomm/didcomm_plaintext_message.dart';
import 'package:ssi/src/didcomm/didcomm_signed_message.dart';
import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';

void main() async {
  KeyStore aliceKeyStore = InMemoryKeyStore();
  GenericWallet aliceWallet = GenericWallet(aliceKeyStore);

  KeyStore bobKeyStore = InMemoryKeyStore();
  GenericWallet bobWallet = GenericWallet(bobKeyStore);

  PublicKey alicePublicKey = await aliceWallet.generateKey();
  PublicKey bobPublicKey = await bobWallet.generateKey();

  DidDocument aliceDidDoc = DidKey.generateDocument(alicePublicKey);
  DidDocument bobDidDoc = DidKey.generateDocument(bobPublicKey);

  DidcommPlaintextMessage message = DidcommPlaintextMessage(
    id: '2fb19055-581d-488e-b357-9d026bee98fc',
    to: [bobDidDoc.id],
    from: aliceDidDoc.id,
    type: 'type',
    body: {"foo": 'bar'},
  );

  Jwk aliceJwk =
      (aliceDidDoc.resolveKeyIds().keyAgreement[0] as VerificationMethod)
          .asJwk();

  Jwk bobJwk =
      (bobDidDoc.resolveKeyIds().keyAgreement[0] as VerificationMethod).asJwk();

  DidcommSignedMessage aliceSignedMessage =
      await DidcommSignedMessage.fromPlaintext(
          wallet: aliceWallet, keyId: alicePublicKey.id, message: message);

  await aliceSignedMessage.verify(aliceJwk);

  DidcommSignedMessage bobsSignedMessage =
      await message.sign(wallet: bobWallet, keyId: bobPublicKey.id);

  await bobsSignedMessage.verify(
      (bobDidDoc.resolveKeyIds().keyAgreement[0] as VerificationMethod)
          .asJwk());

  DidcommEncryptedMessage bobsEncryptedMessage = await bobsSignedMessage
      .encrypt(
          wallet: bobWallet,
          keyId: bobPublicKey.id,
          recipientPublicKeyJwks: [aliceJwk.toJson()]);

  DidcommSignedMessage bobsDecrypytedSignedMessage = await bobsEncryptedMessage
          .decrypt(wallet: aliceWallet, keyId: alicePublicKey.id)
      as DidcommSignedMessage;

  await bobsDecrypytedSignedMessage.verify(bobJwk);
  print(bobsDecrypytedSignedMessage.payload);
}
