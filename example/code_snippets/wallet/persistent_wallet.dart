import 'dart:typed_data';
import 'package:ssi/ssi.dart';

void main() async {
  final dataToSign = Uint8List.fromList([1, 2, 3]);

  // Create generic wallet
  // WARNING: InMemoryKeyStore is not secure for production use.
  // Replace with a secure storage implementation (e.g., Flutter Secure Storage).
  final keyStore = InMemoryKeyStore();
  // Initialize the PersistentWallet with the chosen key store.
  final wallet = PersistentWallet(keyStore);

  // --- P256 Key Operations ---
  print('\n--- P256 Key Operations ---');

  // Generate a P256 key pair. The key ID is returned along with public key info.
  final p256key = await wallet.generateKey(keyType: KeyType.p256);
  print(
      'P256 key pair created. Id: ${p256key.id}, Public key: ${p256key.publicKey.bytes.sublist(1, 9)}...');

  // Sign a sample payload using the generated P256 key ID.
  print('Signing payload with P256 key...');
  final signatureP256 = await wallet.sign(dataToSign, keyId: p256key.id);
  print('Signature: ${signatureP256.sublist(1, 9)}...');

  // Verify the signature using the same P256 key ID and original data.
  print('Verifying P256 signature...');
  final verificationP256 = await wallet.verify(dataToSign,
      signature: signatureP256, keyId: p256key.id);
  assert(verificationP256, 'Verification failed');
  print('Verification succeeded');

  // --- Ed25519 Key Operations ---
  print('\n--- Ed25519 Key Operations ---');

  // Generate an Ed25519 key pair.
  final ed25519key = await wallet.generateKey(keyType: KeyType.ed25519);
  print(
      'Ed25519 key pair created. Public key: ${ed25519key.publicKey.bytes.sublist(1, 9)}...');

  // Sign the same payload using the generated Ed25519 key ID.
  print('Signing payload with Ed25519 key...');
  final signatureEd25519 = await wallet.sign(dataToSign, keyId: ed25519key.id);
  print('Signature: ${signatureEd25519.sublist(1, 9)}...');

  // Verify the signature using the Ed25519 key ID.
  print('Verifying Ed25519 signature...');
  final verificationEd25519 = await wallet.verify(dataToSign,
      signature: signatureEd25519, keyId: ed25519key.id);
  assert(verificationEd25519, 'Verification failed');
  print('Verification succeeded');

  print('\n--- Encryption/Decryption ---');

  // --- Single-Party Encryption/Decryption (P256) ---
  print('\n--- Single-Party (P256) ---');
  final plainText = Uint8List.fromList([10, 20, 30, 40, 50]);
  print('Plaintext: $plainText');

  // Encrypt using the P256 key. When no peer public key is provided,
  // an ephemeral key pair is generated internally for ECDH, and the
  // ephemeral public key is prepended to the ciphertext.
  print('Encrypting using ${p256key.id} (single-party mode)...');
  final encryptedSingleParty = await wallet.encrypt(
    plainText,
    keyId: p256key.id,
  );
  print(
      'Encrypted data (single-party): ${encryptedSingleParty.sublist(1, 9)}...');

  // Decrypt using the same P256 key. When no peer public key is provided,
  // the wallet expects the ephemeral public key to be prepended to the
  // ciphertext to compute the shared secret.
  print('Decrypting using ${p256key.id} (single-party mode)...');
  final decryptedSingleParty = await wallet.decrypt(
    encryptedSingleParty,
    keyId: p256key.id,
  );
  print('Decrypted data (single-party): $decryptedSingleParty');

  // --- Two-Party Encryption/Decryption (P256) ---
  print('\n--- Two-Party (P256) ---');
  // Create a second wallet for Bob
  final bobKeyStore = InMemoryKeyStore();
  final bobWallet = PersistentWallet(bobKeyStore);

  // Generate a P256 key pair for Bob in his wallet.
  final bobP256key = await bobWallet.generateKey(keyType: KeyType.p256);
  print(
      'Bob P256 key pair created. Public key: ${bobP256key.publicKey.bytes.sublist(1, 9)}...');

  // Alice encrypts data for Bob using her private key (identified by p256key.id)
  // and Bob's public key (bobP256key.bytes).
  print(
      'Alice encrypting for Bob using her key ${p256key.id} and Bob\'s public key...');
  final encryptedForBob = await wallet.encrypt(
    plainText,
    keyId: p256key.id, // Alice's key ID
    publicKey: bobP256key.publicKey.bytes, // Bob's public key
  );
  print('Encrypted data (for Bob): ${encryptedForBob.sublist(1, 9)}...');

  // Bob decrypts the data using his private key (identified by bobP256key.id)
  // and Alice's public key (p256key.bytes).
  print(
      'Bob decrypting using his key ${bobP256key.id} and Alice\'s public key...');
  final decryptedByBob = await bobWallet.decrypt(
    encryptedForBob,
    keyId: bobP256key.id, // Bob's key ID
    publicKey: p256key.publicKey.bytes, // Alice's public key
  );
  print('Decrypted data (by Bob): $decryptedByBob');

  // --- Two-Party Encryption/Decryption (Ed25519) ---
  print('\n--- Two-Party (Ed25519) ---');

  // Create a third wallet for Charlie (using Ed25519 for this example)
  final charlieKeyStore = InMemoryKeyStore();
  final charlieWallet = PersistentWallet(charlieKeyStore);

  // Generate an Ed25519 key pair for Charlie in his wallet.
  final charlieEd25519key =
      await charlieWallet.generateKey(keyType: KeyType.ed25519);
  print('Charlie Ed25519 key pair created.');

  // Get the corresponding X25519 public keys for ECDH
  final aliceX25519PublicKey = await wallet.getX25519PublicKey(ed25519key.id);
  final charlieX25519PublicKey =
      await charlieWallet.getX25519PublicKey(charlieEd25519key.id);
  print(
      'Alice X25519 Public Key: ${aliceX25519PublicKey.bytes.sublist(1, 9)}...');
  print(
      'Charlie X25519 Public Key: ${charlieX25519PublicKey.bytes.sublist(1, 9)}...');

  // Alice encrypts data for Charlie using her Ed25519 private key
  // and Charlie's X25519 public key.
  print(
      'Alice encrypting for Charlie using her key ${ed25519key.id} and Charlie\'s X25519 public key...');
  final encryptedForCharlie = await wallet.encrypt(
    plainText,
    keyId: ed25519key.id,
    publicKey: charlieX25519PublicKey.bytes,
  );
  print(
      'Encrypted data (for Charlie): ${encryptedForCharlie.sublist(1, 9)}...');

  // Charlie decrypts the data using his Ed25519 private key
  // and Alice's X25519 public key.
  print(
      'Charlie decrypting using his key ${charlieEd25519key.id} and Alice\'s X25519 public key...');
  final decryptedByCharlie = await charlieWallet.decrypt(
    encryptedForCharlie,
    keyId: charlieEd25519key.id,
    publicKey: aliceX25519PublicKey.bytes,
  );
  print('Decrypted data (by Charlie): $decryptedByCharlie');
}
