import 'dart:convert';
import 'dart:typed_data';

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
///
/// 2. Have base64-encoded Ed25519 public and private keys ready
Future<void> main() async {
  // Example base64-encoded Ed25519 keys
  // In a real application, these would come from your key generation process
  const publicKeyBase64 = 'dGVzdFB1YmxpY0tleQ=='; // Replace with actual public key
  const privateKeyBase64 = 'dGVzdFByaXZhdGVLZXk='; // Replace with actual private key

  try {
    print('Registering did:cheqd on testnet...');
    
    // Register the DID using the provided keys
    final registeredDid = await DidCheqd.register(
      publicKeyBase64,
      privateKeyBase64,
      // Optional: specify custom registrar URL
      // registrarUrl: 'http://localhost:3000',
    );
    
    print('Successfully registered DID: $registeredDid');
    
    // Verify the registration by resolving the DID
    print('Resolving the registered DID...');
    final didDocument = await DidCheqd.resolve(registeredDid);
    print('DID Document:');
    print(jsonEncode(didDocument.toJson()));
    
  } catch (e) {
    print('Error registering DID: $e');
  }
}

/// Helper function to generate example Ed25519 keys
/// This is just for demonstration - in real usage, you'd use proper key generation
Map<String, String> generateExampleKeys() {
  // Generate random bytes for demonstration
  final random = Uint8List.fromList(List.generate(32, (index) => index));
  
  return {
    'publicKey': base64Encode(random),
    'privateKey': base64Encode(random),
  };
}
