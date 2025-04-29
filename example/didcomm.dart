import 'package:ssi/ssi.dart';

void main() async {
  final aliceKeyStore = InMemoryKeyStore();
  final aliceWallet = GenericWallet(aliceKeyStore);

  final bobKeyStore = InMemoryKeyStore();
  final bobWallet = GenericWallet(bobKeyStore);

  final aliceKeyPair = await aliceWallet.generateKey();
  final bobKeyPair = await bobWallet.generateKey();

  final aliceDidDoc = DidKey.generateDocument(aliceKeyPair.publicKey);
  final bobDidDoc = DidKey.generateDocument(bobKeyPair.publicKey);

  final aliceJwk =
      (aliceDidDoc.resolveKeyIds().keyAgreement[0] as VerificationMethod)
          .asJwk();

  final bobJwk =
      (bobDidDoc.resolveKeyIds().keyAgreement[0] as VerificationMethod).asJwk();

  final aliceSigner = DidSigner(
    didDocument: aliceDidDoc,
    keyPair: aliceKeyPair,
    didKeyId: aliceDidDoc.verificationMethod[0].id,
    signatureScheme: SignatureScheme.ecdsa_p256_sha256,
  );

  // ==== sign using DidcommPlaintextMessage.sign method
  final message = DidcommPlaintextMessage.to(bobDidDoc.id,
      type: 'type', body: {'foo': 'bar'});

  final aliceSignedMessageUsingMessageDirectly =
      await message.sign(aliceSigner);

  await aliceSignedMessageUsingMessageDirectly.verifyUsingJwk(aliceJwk);
  // ====

  // ==== sign using DidcommSignedMessage.fromPlaintext method
  final aliceSignedMessage =
      await DidcommSignedMessage.fromPlaintext(message, signer: aliceSigner);

  await aliceSignedMessage.verifyUsingJwk(aliceJwk);
  // ====

  final bobSigner = DidSigner(
    didDocument: bobDidDoc,
    keyPair: bobKeyPair,
    didKeyId: bobDidDoc.verificationMethod[0].id,
    signatureScheme: SignatureScheme.ecdsa_p256_sha256,
  );

  final bobsSignedMessage = await message.sign(bobSigner);

  final didVerifier = await DidVerifier.create(
      algorithm: SignatureScheme.ecdsa_p256_sha256, issuerDid: bobDidDoc.id);
  await bobsSignedMessage.verify(didVerifier);

  final bobsEncryptedMessage = await bobsSignedMessage.encrypt(
      wallet: bobWallet,
      keyId: bobKeyPair.id,
      recipientPublicKeyJwks: [aliceJwk.toJson()]);

  final getFromJson =
      DidcommEncryptedMessage.fromJson(bobsEncryptedMessage.toJson());

  final bobsDecrypytedSignedMessage = await getFromJson.decrypt(
      wallet: aliceWallet, keyId: aliceKeyPair.id) as DidcommSignedMessage;

  await bobsDecrypytedSignedMessage.verifyUsingJwk(bobJwk);
  print(bobsDecrypytedSignedMessage.payload);
}
