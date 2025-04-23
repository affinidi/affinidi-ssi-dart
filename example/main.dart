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

  // from wallet with root key
  print('\n--- Root Key Operations ---');
  final data = Uint8List.fromList([1, 2, 3]);
  print('Data to sign: ${hexEncode(data)}');
  print('Signing with root key (${Bip32Wallet.rootKeyId})...');
  final signature = await wallet.sign(data, keyId: Bip32Wallet.rootKeyId);
  print('Root key signature: ${hexEncode(signature)}');
  print('Verifying root key signature...');
  final isRootSignatureValid = await wallet.verify(data,
      signature: signature, keyId: Bip32Wallet.rootKeyId);
  print('Root key signature verification result: $isRootSignatureValid');
  assert(isRootSignatureValid, "Root key verification failed");

  final rootKey = await wallet.getPublicKey(Bip32Wallet.rootKeyId);
  final rootDidKey = DidKey.generateDocument(rootKey);
  print('root did: ${rootDidKey.id}');

  // from derived key pair
  print("Signing and verifying from profile key");
  final profileKeyId = "1234-0";
  print('\n--- Profile Key 1 Operations ($profileKeyId) ---');
  print('Generating profile key 1 ($profileKeyId)...');
  final profileKey = await wallet.generateKey(keyId: profileKeyId);
  print('Profile key 1 generated. Public key: ${profileKey.bytes}');
  print('Signing with profile key 1 ($profileKeyId)...');
  final profileSignature = await wallet.sign(data, keyId: profileKeyId);
  print('Profile key 1 signature: ${hexEncode(profileSignature)}');
  print('Verifying profile key 1 signature...');
  final isProfileSignatureValid = await wallet.verify(data,
      signature: profileSignature, keyId: profileKeyId);
  print(
      'Profile key 1 signature verification result: $isProfileSignatureValid');
  assert(isProfileSignatureValid, "Profile key 1 verification failed");
  final profileDidKey = DidKey.generateDocument(profileKey);
  print('profile did: ${profileDidKey.id}');

  // second profile key
  final profileKeyId2 = "1234-1";
  print('\n--- Profile Key 2 Operations ($profileKeyId2) ---');
  print('Generating profile key 2 ($profileKeyId2)...');
  await wallet.generateKey(keyId: profileKeyId2);
  print('Signing with profile key 2 ($profileKeyId2)...');
  final profileSignature2 = await wallet.sign(data, keyId: profileKeyId2);
  print('Profile key 2 signature: ${hexEncode(profileSignature2)}');
  print('Verifying profile key 2 signature...');
  final isProfileSignature2Valid = await wallet.verify(data,
      signature: profileSignature2, keyId: profileKeyId2);
  print(
      'Profile key 2 signature verification result: $isProfileSignature2Valid');
  assert(isProfileSignature2Valid, "Profile key 2 verification failed");

  print('\n--- Encryption/Decryption ---');

  // --- Single-Party Encryption/Decryption (Secp256k1) ---
  print('\n--- Single-Party (Secp256k1) ---');
  final plainText = Uint8List.fromList([10, 20, 30, 40, 50, 60]);
  print('Plaintext: $plainText');

  // Encrypt using the profile key (no peer public key provided)
  // This uses an ephemeral key internally for ECDH.
  print('Encrypting using $profileKeyId (single-party mode)...');
  final encryptedSingleParty = await wallet.encrypt(
    plainText,
    keyId: profileKeyId,
  );
  print('Encrypted data (single-party): $encryptedSingleParty');

  // Decrypt using the same profile key
  // The wallet extracts the ephemeral public key from the ciphertext.
  print('Decrypting using $profileKeyId (single-party mode)...');
  final decryptedSingleParty = await wallet.decrypt(
    encryptedSingleParty,
    keyId: profileKeyId,
  );
  print('Decrypted data (single-party): $decryptedSingleParty');
  print('Single-party encryption/decryption successful!');

  // --- Two-Party Encryption/Decryption (Secp256k1) ---
  print('\n--- Two-Party (Secp256k1) ---');
  // Create a second wallet for Bob using a different seed
  final bobSeed = hexDecode(
    'b2883c25545589203b66fc5e6f5a04878cc1078311be19525b10d87897fe3ddf', // Different seed for Bob
  );
  final bobWallet = Bip32Wallet.fromSeed(bobSeed);

  // Generate a key pair for Bob
  const bobKeyId = '5678-0'; // Bob's key ID
  final bobKey = await bobWallet.generateKey(keyId: bobKeyId);
  print('Bob key pair created. Public key: ${bobKey.bytes}');

  // Alice (using 'wallet' and 'profileKeyId') encrypts data for Bob
  print(
      'Alice encrypting for Bob using her key $profileKeyId and Bob\'s public key...');
  final encryptedForBob = await wallet.encrypt(
    plainText,
    keyId: profileKeyId, // Alice's key ID
    publicKey: bobKey.bytes, // Bob's public key
  );
  print('Encrypted data (for Bob): $encryptedForBob');

  // Bob decrypts the data using Alice's public key
  // Retrieve Alice's public key first (we already have 'profileKey' from earlier)
  print(
      'Bob decrypting using his key $bobKeyId and Alice\'s public key ($profileKeyId)...');
  final decryptedByBob = await bobWallet.decrypt(
    encryptedForBob,
    keyId: bobKeyId, // Bob's key ID
    publicKey: profileKey.bytes, // Alice's public key
  );
  print('Decrypted data (by Bob): $decryptedByBob');
  print('Two-party encryption/decryption successful!');
}
