import 'dart:typed_data';
import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';
import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';

void main() async {
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );

  print('\n--- Bip32 Wallet Operations (Secp256k1) ---');

  // WARNING: InMemoryKeyStore is not secure for production use.
  // Replace with a secure storage implementation (e.g., Flutter Secure Storage).
  final keyStore = InMemoryKeyStore();

  final wallet = await Bip32Wallet.fromSeed(seed, keyStore);
  print('Bip32 wallet created from seed.');

  // Use a standard BIP44 path for the first account
  const account0Key0DerivationPath = "m/44'/60'/0'/0/0";
  const account0Key0Id = 'account0-key0';
  print(
      '\n--- Account 0 Key 0 Operations ($account0Key0Id, $account0Key0DerivationPath) ---');
  final data = Uint8List.fromList([1, 2, 3]);
  print('Data to sign: ${hexEncode(data)}');

  // Derive the account 0 key
  print('Deriving account 0 key 0 ($account0Key0Id)...');
  final account0Key0 = await wallet.deriveKey(
      keyId: account0Key0Id, derivationPath: account0Key0DerivationPath);
  print('Account 0 key 0 derived. Public key: ${account0Key0.publicKey.bytes}');

  print('Signing with account 0 key 0 ($account0Key0Id)...');
  final signature = await wallet.sign(data, keyId: account0Key0.id);
  print('Account 0 key 0 signature: ${hexEncode(signature)}');
  print('Verifying account 0 key 0 signature...');
  final isRootSignatureValid =
      await wallet.verify(data, signature: signature, keyId: account0Key0.id);
  print('Account 0 key 0 signature verification result: $isRootSignatureValid');
  assert(isRootSignatureValid, "Account 0 key 0 verification failed");

  final account0Key0DidKey = DidKey.generateDocument(account0Key0);
  print('Account 0 Key 0 DID: ${account0Key0DidKey.id}');

  // Use the next key in account 0
  const account0Key1DerivationPath = "m/44'/60'/0'/0/1";
  final account0Key1Id = "account0-key1";
  print(
      '\n--- Account 0 Key 1 Operations ($account0Key1Id, $account0Key1DerivationPath) ---');
  print('Deriving account 0 key 1 ($account0Key1Id)...');
  final account0Key1 = await wallet.deriveKey(
      keyId: account0Key1Id, derivationPath: account0Key1DerivationPath);
  print('Account 0 key 1 derived. Public key: ${account0Key1.bytes}');
  print('Signing with account 0 key 1 ($account0Key1Id)...');
  final account0Key1Signature = await wallet.sign(data, keyId: account0Key1Id);
  print('Account 0 key 1 signature: ${hexEncode(account0Key1Signature)}');
  print('Verifying account 0 key 1 signature...');
  final isProfileSignatureValid = await wallet.verify(data,
      signature: account0Key1Signature, keyId: account0Key1Id);
  print(
      'Account 0 key 1 signature verification result: $isProfileSignatureValid');
  assert(isProfileSignatureValid, "Account 0 key 1 verification failed");
  final account0Key1DidKey = DidKey.generateDocument(account0Key1);
  print('Account 0 key 1 DID: ${account0Key1DidKey.id}');

  print('\n--- Encryption/Decryption ---');

  // --- Single-Party Encryption/Decryption (Secp256k1) ---
  print('\n--- Single-Party (Secp256k1) ---');
  final plainText = Uint8List.fromList([10, 20, 30, 40, 50, 60]);
  print('Plaintext: $plainText');

  // Encrypt using the profile key (no peer public key provided)
  // This uses an ephemeral key internally for ECDH.
  print('Encrypting using $account0Key1Id (single-party mode)...');
  final encryptedSingleParty = await wallet.encrypt(
    plainText,
    keyId: account0Key1Id,
  );
  print('Encrypted data (single-party): $encryptedSingleParty');

  // Decrypt using the same profile key
  // The wallet extracts the ephemeral public key from the ciphertext.
  print('Decrypting using $account0Key1Id (single-party mode)...');
  final decryptedSingleParty = await wallet.decrypt(
    encryptedSingleParty,
    keyId: account0Key1Id,
  );
  print('Decrypted data (single-party): $decryptedSingleParty');
  print('Single-party encryption/decryption successful!');

  // --- Two-Party Encryption/Decryption (Secp256k1) ---
  print('\n--- Two-Party (Secp256k1) ---');
  // Create a second wallet for Bob using a different seed
  final bobSeed = hexDecode(
    'b2883c25545589203b66fc5e6f5a04878cc1078311be19525b10d87897fe3ddf', // Different seed for Bob
  );
  // Create KeyStore for Bob
  final bobKeyStore = InMemoryKeyStore();
  final bobWallet = await Bip32Wallet.fromSeed(bobSeed, bobKeyStore);

  // Derive a key pair for Bob
  const bobKeyId = 'bob-key-0';
  const bobDerivationPath = "m/44'/0'/0'/0/0";
  final bobKey = await bobWallet.deriveKey(
      keyId: bobKeyId, derivationPath: bobDerivationPath);
  print('Bob key pair created. Public key: ${bobKey.bytes}');

  // Alice (using 'wallet' and 'account0Key1Id') encrypts data for Bob
  print(
      'Alice encrypting for Bob using her key $account0Key1Id and Bob\'s public key...');
  final encryptedForBob = await wallet.encrypt(
    plainText,
    keyId: account0Key1Id, // Alice's key ID
    publicKey: bobKey.bytes, // Bob's public key
  );
  print('Encrypted data (for Bob): $encryptedForBob');

  // Bob decrypts the data using Alice's public key
  // Retrieve Alice's public key first (we already have 'account0Key1' from earlier)
  print(
      'Bob decrypting using his key $bobKeyId and Alice\'s public key ($account0Key1Id)...');
  final decryptedByBob = await bobWallet.decrypt(
    encryptedForBob,
    keyId: bobKeyId, // Bob's key ID
    publicKey: account0Key1.bytes, // Alice's public key
  );
  print('Decrypted data (by Bob): $decryptedByBob');
  print('Two-party encryption/decryption successful!');
}
