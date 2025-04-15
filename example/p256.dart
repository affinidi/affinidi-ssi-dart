import 'dart:typed_data';
import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

void main() async {
  final dataToSign = Uint8List.fromList([1, 2, 3]);

  // Create P256 key pair
  final p256key = P256KeyPair.create(keyId: "MyKeyPair");
  print('P256 key pair created. Public key: ${await p256key.publicKey}');

  // Sing payload
  print('Signing payload...');
  final signature = await p256key.sign(dataToSign);
  print('Signature: ${signature}');

  // Verify signature
  print('Verifying signature...');
  final verifification = await p256key.verify(dataToSign, signature);
  assert(verifification, "Verification failed");
  print('Verification succeeded');

  // Creating key pairs for Alice and Bob
  print('Creating key pairs for Alice and Bob...');
  final keyPairAlice = P256KeyPair.create(keyId: "alice");
  print('Alice key pair created. Public key: ${await keyPairAlice.publicKey}');
  final keyPairBob = P256KeyPair.create(keyId: "bob");
  print('Bob key pair created. Public key: ${await keyPairBob.publicKey}');

  // Compute ECDH (Elliptic Curve Diffie-Hellman) for encryption
  print('Computing ECDH secret...');
  final secretAlice =
      await keyPairAlice.computeEcdhSecret(await keyPairBob.publicKey);
  print('Alice secret: $secretAlice');
  final secretBob =
      await keyPairBob.computeEcdhSecret(await keyPairAlice.publicKey);
  print('Bob secret: $secretBob');

  // Comparing secrets
  assert(
      secretAlice == secretBob, 'Both Alice and Bob must have the same secret');
  print('Success. Alice and Bob secrets are the same.');
}
