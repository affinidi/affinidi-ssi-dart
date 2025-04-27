import 'package:ssi/ssi.dart';

void main() async {
  KeyStore aliceKeyStore = InMemoryKeyStore();
  GenericWallet aliceWallet = GenericWallet(aliceKeyStore);

  KeyStore bobKeyStore = InMemoryKeyStore();
  GenericWallet bobWallet = GenericWallet(bobKeyStore);

  KeyPair aliceKeyPair = await aliceWallet.generateKey();
  KeyPair bobKeyPair = await bobWallet.generateKey();

  DidDocument aliceDidDoc = DidKey.generateDocument(aliceKeyPair.publicKey);
  DidDocument bobDidDoc = DidKey.generateDocument(bobKeyPair.publicKey);

  Jwk aliceJwk =
      (aliceDidDoc.resolveKeyIds().keyAgreement[0] as VerificationMethod)
          .asJwk();

  Jwk bobJwk =
      (bobDidDoc.resolveKeyIds().keyAgreement[0] as VerificationMethod).asJwk();

  DidSigner aliceSigner = DidSigner(
    didDocument: aliceDidDoc,
    keyPair: aliceKeyPair,
    didKeyId: aliceDidDoc.verificationMethod[0].id,
    signatureScheme: SignatureScheme.ecdsa_p256_sha256,
  );

  // ==== sign using DidcommPlaintextMessage.sign method
  DidcommPlaintextMessage message = DidcommPlaintextMessage.to(bobDidDoc.id,
      type: 'type', body: {'foo': 'bar'});

  DidcommSignedMessage aliceSignedMessageUsingMessageDirectly =
      await message.sign(aliceSigner);

  await aliceSignedMessageUsingMessageDirectly.verify(aliceJwk);
  // ====

  // ==== sign using DidcommSignedMessage.fromPlaintext method
  DidcommSignedMessage aliceSignedMessage =
      await DidcommSignedMessage.fromPlaintext(message, signer: aliceSigner);

  await aliceSignedMessage.verify(aliceJwk);
  // ====

  DidSigner bobSigner = DidSigner(
    didDocument: bobDidDoc,
    keyPair: bobKeyPair,
    didKeyId: bobDidDoc.verificationMethod[0].id,
    signatureScheme: SignatureScheme.ecdsa_p256_sha256,
  );

  DidcommSignedMessage bobsSignedMessage = await message.sign(bobSigner);

  await bobsSignedMessage.verify(
      (bobDidDoc.resolveKeyIds().keyAgreement[0] as VerificationMethod)
          .asJwk());

  DidcommEncryptedMessage bobsEncryptedMessage = await bobsSignedMessage
      .encrypt(
          wallet: bobWallet,
          keyId: bobKeyPair.id,
          recipientPublicKeyJwks: [aliceJwk.toJson()]);

  DidcommEncryptedMessage getFromJson =
      DidcommEncryptedMessage.fromJson(bobsEncryptedMessage.toJson());

  DidcommSignedMessage bobsDecrypytedSignedMessage = await getFromJson.decrypt(
      wallet: aliceWallet, keyId: aliceKeyPair.id) as DidcommSignedMessage;

  await bobsDecrypytedSignedMessage.verify(bobJwk);
  print(bobsDecrypytedSignedMessage.payload);
}
