import 'dart:convert';

import 'package:ssi/ssi.dart';

/// Example demonstrating how to register a did:cheqd on testnet
/// using a wallet for secure key management.
///
/// This example shows the complete two-step registration process:
/// 1. Initial registration request
/// 2. Polling for completion with signature verification
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

    // Step 1: Create a wallet for secure key management
    print('1. Creating wallet for secure key management...');
    final keyStore = InMemoryKeyStore();
    final wallet = PersistentWallet(keyStore);

    // Step 2: Generate Ed25519 key pair in the wallet
    print('2. Generating Ed25519 key pair in wallet...');
    final keyPair = await wallet.generateKey(
      keyId: 'cheqd-key',
      keyType: KeyType.ed25519,
    );

    print('Key ID: ${keyPair.id}');
    print('Key Type: ${keyPair.publicKey.type}');
    print('');

    // Step 3: Register the DID on cheqd testnet using wallet
    print('3. Registering did:cheqd on testnet using wallet...');
    print('   This involves:');
    print('   - Initial registration request');
    print('   - Polling for completion with signature verification');
    print('   - Secure signing using wallet (private key never exposed)');

    final registeredDid = await DidCheqd.registerWithWallet(
      wallet,
      keyPair.id,
      // Optional: specify custom registrar URL
      // registrarUrl: 'http://localhost:3000',
    );

    print('✅ Successfully registered DID: $registeredDid');
    print('');

    // Step 4: Verify the registration by resolving the DID
    print('4. Resolving the registered DID...');
    final didDocument = await DidCheqd.resolve(registeredDid);

    print('✅ Successfully resolved DID document:');
    print('DID: ${didDocument.id}');
    print('Controller: ${didDocument.controller}');
    print('Verification Methods: ${didDocument.verificationMethod.length}');
    print('');
    print('Full DID Document (JSON):');
    print(const JsonEncoder.withIndent('  ').convert(didDocument.toJson()));
  } catch (e) {
    print('❌ Error registering DID: $e');

    // Provide helpful error messages
    if (e.toString().contains('Connection refused') ||
        e.toString().contains('Failed to register DID: 500')) {
      print('\n💡 Troubleshooting:');
      print(
          '1. Make sure the cheqd DID registrar is running on http://localhost:3000');
      print('2. Check that all required environment variables are set');
      print(
          '3. Verify the registrar service is properly configured for testnet');
    }
  }
}
