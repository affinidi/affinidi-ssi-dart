import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';

/// Complete example demonstrating did:cheqd registration with proper key generation
///
/// This example shows the complete two-step registration process:
/// 1. How to generate Ed25519 key pairs
/// 2. How to encode them in base64 format
/// 3. How to register a did:cheqd on testnet (initial request + polling with signature)
/// 4. How to resolve and verify the registered DID
///
/// Prerequisites:
/// 1. Start the cheqd DID registrar service locally:
///    - Clone: https://github.com/cheqd/did-registrar
///    - Install: npm install && npm run build
///    - Set environment variables (see README in the repository)
///    - Start: npm start (runs on http://localhost:3000)
Future<void> main() async {
  try {
    print('=== Cheqd DID Registration Example ===\n');
    
    // Step 1: Generate Ed25519 key pair
    print('1. Generating Ed25519 key pair...');
    final (keyPair, privateKeyBytes) = Ed25519KeyPair.generate();
    final publicKey = keyPair.publicKey;
    
    // Step 2: Encode keys in base64 format
    print('2. Encoding keys in base64 format...');
    final publicKeyBase64 = base64Encode(publicKey.bytes);
    final privateKeyBase64 = base64Encode(privateKeyBytes);
    
    print('Public Key (base64): $publicKeyBase64');
    print('Private Key (base64): $privateKeyBase64');
    print('Key Type: ${publicKey.type}');
    print('');
    
    // Step 3: Register the DID on cheqd testnet (two-step process)
    print('3. Registering did:cheqd on testnet...');
    print('   This involves:');
    print('   - Initial registration request');
    print('   - Polling for completion with signature verification');
    
    final registeredDid = await DidCheqd.register(
      publicKeyBase64,
      privateKeyBase64,
    );
    
    print('✅ Successfully registered DID: $registeredDid');
    print('');
    
    // Step 4: Resolve and verify the registered DID
    print('4. Resolving the registered DID...');
    final didDocument = await DidCheqd.resolve(registeredDid);
    
    print('✅ Successfully resolved DID document:');
    print('DID: ${didDocument.id}');
    print('Controller: ${didDocument.controller}');
    print('Verification Methods: ${didDocument.verificationMethod.length}');
    
    // Display verification method details
    for (final vm in didDocument.verificationMethod) {
      print('  - ID: ${vm.id}');
      print('    Type: ${vm.type}');
      print('    Controller: ${vm.controller}');
    }
    
    print('');
    print('Full DID Document (JSON):');
    print(const JsonEncoder.withIndent('  ').convert(didDocument.toJson()));
    
  } catch (e) {
    print('❌ Error: $e');
    
    // Provide helpful error messages
    if (e.toString().contains('Connection refused') || 
        e.toString().contains('Failed to register DID: 500')) {
      print('\n💡 Troubleshooting:');
      print('1. Make sure the cheqd DID registrar is running on http://localhost:3000');
      print('2. Check that all required environment variables are set');
      print('3. Verify the registrar service is properly configured for testnet');
    }
  }
}

/// Alternative example using a wallet to generate keys
Future<void> walletBasedExample() async {
  try {
    print('=== Wallet-based Cheqd DID Registration ===\n');
    
    // Create a BIP32 Ed25519 wallet
    final seed = Uint8List.fromList(List.generate(32, (index) => index));
    final wallet = Bip32Ed25519Wallet.fromSeed(seed);
    
    // Generate a key pair from the wallet using a derivation path
    final key = await wallet.generateKey(keyId: 'm/0/0', keyType: KeyType.ed25519);
    final publicKey = key.publicKey;
    
    // For this example, we'll use the direct key generation approach
    // since the wallet doesn't expose private key bytes directly
    final (directKeyPair, privateKeyBytes) = Ed25519KeyPair.generate();
    
    // Encode keys in base64
    final publicKeyBase64 = base64Encode(publicKey.bytes);
    final privateKeyBase64 = base64Encode(privateKeyBytes);
    
    print('Generated keys:');
    print('Public Key ID: ${publicKey.id}');
    print('Public Key (base64): $publicKeyBase64');
    print('');
    
    // Register the DID
    final registeredDid = await DidCheqd.register(
      publicKeyBase64,
      privateKeyBase64,
    );
    
    print('✅ Registered DID: $registeredDid');
    
    // Resolve to verify
    final didDocument = await DidCheqd.resolve(registeredDid);
    print('✅ Verified registration - DID document resolved successfully');
    print('DID: ${didDocument.id}');
    
  } catch (e) {
    print('❌ Error in wallet-based example: $e');
  }
}
