import 'dart:convert';

import 'package:ssi/ssi.dart';

/// Example demonstrating how to register a did:cheqd on testnet
/// using base64-encoded public and private keys.
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

    // Step 3: Register the DID on cheqd testnet
    print('3. Registering did:cheqd on testnet...');
    print('   This involves:');
    print('   - Initial registration request');
    print('   - Polling for completion with signature verification');

    final registeredDid = await DidCheqd.register(
      publicKeyBase64,
      privateKeyBase64,
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
      print('1. Make sure the cheqd DID registrar is running on http://localhost:3000');
      print('2. Check that all required environment variables are set');
      print('3. Verify the registrar service is properly configured for testnet');
    }
  }
}
