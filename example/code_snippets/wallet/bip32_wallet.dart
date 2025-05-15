import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  print('\n--- Bip32 Wallet Operations (Secp256k1) ---');

  final wallet = Bip32Wallet.fromSeed(seed);
  print('Bip32 wallet created from seed.');

  // Use a standard BIP44 path for the first key
  const key0DerivationPath = "m/44'/60'/0'/0'/0'";
  print('\n--- Key 0 Operations ---');
  final data = Uint8List.fromList([1, 2, 3]);
  print('Data to sign: ${hexEncode(data)}');

  // Derive key 0
  print('Deriving key 0 ($key0DerivationPath)...');
  final key0 = await wallet.generateKey(keyId: key0DerivationPath);
  print('Key 0 derived. Public key: ${key0.publicKey.bytes.sublist(1, 5)}...');

  print('Signing with key 0 ($key0DerivationPath)...');
  final signature = await wallet.sign(data, keyId: key0.id);
  print('Key 0 signature: ${signature.sublist(1, 9)}...');
  print('Verifying key 0 signature...');
  final isRootSignatureValid =
      await wallet.verify(data, signature: signature, keyId: key0.id);
  print('Key 0 signature verification result: $isRootSignatureValid');
  assert(isRootSignatureValid, 'Key 0 verification failed');

  final key0DidKey = DidKey.generateDocument(key0.publicKey);
  print('Key 0 DID: ${key0DidKey.id}');

  // Derive key 1
  const key1DerivationPath = "m/44'/60'/0'/0'/1'";
  print('\n--- Key 1 Operations ---');
  print('Deriving key 1 ($key1DerivationPath)...');
  final key1 = await wallet.generateKey(keyId: key1DerivationPath);
  print('Key 1 derived. Public key: ${key1.publicKey.bytes.sublist(1, 9)}...');
  print('Signing with key 1 ($key1DerivationPath)...');
  final key1Signature = await wallet.sign(data, keyId: key1DerivationPath);
  print('Key 1 signature: ${key1Signature.sublist(1, 9)}...');
  print('Verifying key 1 signature...');
  final isProfileSignatureValid = await wallet.verify(data,
      signature: key1Signature, keyId: key1DerivationPath);
  print('Key 1 signature verification result: $isProfileSignatureValid');
  assert(isProfileSignatureValid, 'Key 1 verification failed');
  final key1DidKey = DidKey.generateDocument(key1.publicKey);
  print('Key 1 DID: ${key1DidKey.id}');

  // --- Single-Party Encryption/Decryption (Secp256k1) ---
  print('\n--- Single-Party (Secp256k1) Encryption/Decryption ---');
  final plainText = Uint8List.fromList([10, 20, 30, 40, 50, 60]);
  print('Plaintext: $plainText');

  // Encrypt using the profile key (no peer public key provided)
  // This uses an ephemeral key internally for ECDH.
  print('Encrypting using key $key1DerivationPath (single-party mode)...');
  final encryptedSingleParty = await wallet.encrypt(
    plainText,
    keyId: key1DerivationPath,
  );
  print(
      'Encrypted data (single-party): ${encryptedSingleParty.sublist(1, 9)}...');

  // Decrypt using the same profile key
  // The wallet extracts the ephemeral public key from the ciphertext.
  print('Decrypting using key $key1DerivationPath (single-party mode)...');
  final decryptedSingleParty = await wallet.decrypt(
    encryptedSingleParty,
    keyId: key1DerivationPath,
  );
  print('Decrypted data (single-party): $decryptedSingleParty');
  print('Single-party encryption/decryption successful!');

  // --- Two-Party Encryption/Decryption (Secp256k1) ---
  print('\n--- Two-Party (Secp256k1) Encryption/Decryption ---');
  // Create a second wallet for Bob using a different seed
  final bobSeed = hexDecode(
    'b2883c25545589203b66fc5e6f5a04878cc1078311be19525b10d87897fe3ddf', // Different seed for Bob
  );
  // Create KeyStore for Bob
  final bobWallet = Bip32Wallet.fromSeed(bobSeed);

  // Derive a key pair for Bob
  const bobDerivationPath = "m/44'/0'/0'/0/0";
  final bobKey = await bobWallet.generateKey(keyId: bobDerivationPath);
  print(
      'Bob key pair created. Public key: ${bobKey.publicKey.bytes.sublist(1, 9)}...');

  // Alice (using 'wallet' and 'account0Key1Id') encrypts data for Bob
  print(
      'Alice encrypting for Bob using her key $key1DerivationPath and Bob\'s public key...');
  final encryptedForBob = await wallet.encrypt(
    plainText,
    keyId: key1DerivationPath, // Alice's key ID
    publicKey: bobKey.publicKey.bytes, // Bob's public key
  );
  print('Encrypted data (for Bob): ${encryptedForBob.sublist(1, 9)}...');

  // Bob decrypts the data using Alice's public key
  // Retrieve Alice's public key first (we already have 'account0Key1' from earlier)
  print(
      'Bob decrypting using his key $bobDerivationPath and Alice\'s public key ($key1DerivationPath)...');
  final decryptedByBob = await bobWallet.decrypt(
    encryptedForBob,
    keyId: bobDerivationPath, // Bob's key ID
    publicKey: key1.publicKey.bytes, // Alice's public key
  );
  print('Decrypted data (by Bob): $decryptedByBob');
  print('Two-party encryption/decryption successful!');
}
