import 'dart:typed_data';
import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';

void main() async {
  final dataToSign = Uint8List.fromList([1, 2, 3]);

  // Create generic wallet
  // WARNING: This key store should be replaced with a secure storage
  final keyStore = InMemoryKeyStore();
  final wallet = GenericWallet(keyStore);

  // Create P256 key pair
  final p256key = await wallet.generateKey(keyType: KeyType.p256);
  print('P256 key pair created. Public key: ${p256key.bytes}');

  // Sing payload
  print('Signing payload...');
  final signatureP256 = await wallet.sign(dataToSign, keyId: p256key.id);
  print('Signature: $signatureP256');

  // Verify signature
  print('Verifying signature...');
  final verificationP256 = await wallet.verify(dataToSign,
      signature: signatureP256, keyId: p256key.id);
  assert(verificationP256, "Verification failed");
  print('Verification succeeded');

  // Create Ed25519 key pair
  final ed25519key = await wallet.generateKey(keyType: KeyType.ed25519);
  print('Ed25519 key pair created. Public key: ${ed25519key.bytes}');

  // Sing payload
  print('Signing payload...');
  final signatureEd25519 = await wallet.sign(dataToSign, keyId: ed25519key.id);
  print('Signature: $signatureEd25519');

  // Verify signature
  print('Verifying signature...');
  final verificationEd25519 = await wallet.verify(dataToSign,
      signature: signatureEd25519, keyId: ed25519key.id);
  assert(verificationEd25519, "Verification failed");
  print('Verification succeeded');

  // // Creating key pairs for Alice and Bob
  // print('Creating key pairs for Alice and Bob...');
  // final keyPairAlice = P256KeyPair();
  // print('Alice key pair created. Public key: ${await keyPairAlice.publicKey}');
  // final keyPairBob = P256KeyPair();
  // print('Bob key pair created. Public key: ${await keyPairBob.publicKey}');
  //
  // // Compute ECDH (Elliptic Curve Diffie-Hellman) for encryption
  // print('Computing ECDH secret...');
  // final secretAlice =
  //     await keyPairAlice.computeEcdhSecret(await keyPairBob.publicKey);
  // print('Alice secret: $secretAlice');
  // final secretBob =
  //     await keyPairBob.computeEcdhSecret(await keyPairAlice.publicKey);
  // print('Bob secret: $secretBob');
  //
  // // Comparing secrets
  // assert(
  //     secretAlice == secretBob, 'Both Alice and Bob must have the same secret');
  // print('Success. Alice and Bob secrets are the same.');
}
