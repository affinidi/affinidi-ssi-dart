import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

void main() async {
  print('=== DID Manager Basic Example ===\n');

  // Step 1: Create wallet
  print('1. Creating wallet...');
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );
  final wallet = Bip32Wallet.fromSeed(seed);
  print('Wallet created from seed.');

  // Step 2: Create DID Manager
  print('\n2. Creating DID Managers...');

  // Create did:key manager
  print('\n--- did:key Manager ---');
  final didKeyManager = DidKeyManager(
    keyMappingStore: InMemoryDidKeyMappingStore(),
    documentReferenceStore: InMemoryDidDocumentReferenceStore(),
    wallet: wallet,
  );

  // Generate a key for did:key
  final keyForDidKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'");
  print(
      'Generated key for did:key. Public key: ${keyForDidKey.publicKey.bytes.sublist(1, 9)}...');

  // Add verification method and create DID document
  await didKeyManager.addVerificationMethod(keyForDidKey.id);
  final didKeyDocument = await didKeyManager.getDidDocument();
  print('did:key DID: ${didKeyDocument.id}');
  print('Verification methods: ${didKeyDocument.verificationMethod.length}');

  // Create did:peer manager
  print('\n--- did:peer Manager ---');
  final didPeerManager = DidPeerManager(
    keyMappingStore: InMemoryDidKeyMappingStore(),
    documentReferenceStore: InMemoryDidDocumentReferenceStore(),
    wallet: wallet,
  );

  // Generate keys for did:peer
  final authKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/1'");
  final keyAgreementKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/2'");
  print(
      'Generated authentication key. Public key: ${authKey.publicKey.bytes.sublist(1, 9)}...');
  print(
      'Generated key agreement key. Public key: ${keyAgreementKey.publicKey.bytes.sublist(1, 9)}...');

  // Add verification methods and create DID document
  final authVmId = await didPeerManager.addVerificationMethod(authKey.id);
  final kaVmId = await didPeerManager.addVerificationMethod(keyAgreementKey.id);
  await didPeerManager.addAuthentication(authVmId.verificationMethodId);
  await didPeerManager.addKeyAgreement(kaVmId.verificationMethodId);
  final didPeerDocument = await didPeerManager.getDidDocument();
  print('did:peer DID: ${didPeerDocument.id}');
  print('Verification methods: ${didPeerDocument.verificationMethod.length}');
  print('Authentication methods: ${didPeerDocument.authentication.length}');
  print('Key agreement methods: ${didPeerDocument.keyAgreement.length}');

  // Step 3: Sign and verify
  print('\n3. Signing and verifying data...');
  final data = Uint8List.fromList([1, 2, 3, 4, 5]);
  print('Data to sign: ${hexEncode(data)}');

  // Sign with did:key
  print('\n--- Signing with did:key ---');
  final didKeyVmId = didKeyDocument.verificationMethod[0].id;
  // Key mapping is already set up by addVerificationMethod

  final didKeySignature = await didKeyManager.sign(data, didKeyVmId);
  print('Signature: ${didKeySignature.sublist(0, 8)}...');

  final didKeyVerified = await didKeyManager.verify(
    data,
    didKeySignature,
    didKeyVmId,
  );
  print('Verification result: $didKeyVerified');

  // Sign with did:peer
  print('\n--- Signing with did:peer ---');
  // Use the verification method ID from above
  final didPeerVmId = authVmId.verificationMethodId;
  // Key mapping is already set up by addVerificationMethod

  final didPeerSignature = await didPeerManager.sign(data, didPeerVmId);
  print('Signature: ${didPeerSignature.sublist(0, 8)}...');

  final didPeerVerified = await didPeerManager.verify(
    data,
    didPeerSignature,
    didPeerVmId,
  );
  print('Verification result: $didPeerVerified');

  // Step 4: Get DID Signer for use with credentials
  print('\n4. Getting DID Signer for credential operations...');
  final didKeySigner = await didKeyManager.getSigner(didKeyVmId);
  print('did:key signer created:');
  // DID is available in the didDocument passed to create the signer
  print('  - Key ID: ${didKeySigner.keyId}');
  print('  - Signature scheme: ${didKeySigner.signatureScheme}');

  final didPeerSigner = await didPeerManager.getSigner(didPeerVmId);
  print('\ndid:peer signer created:');
  // DID is available in the didDocument passed to create the signer
  print('  - Key ID: ${didPeerSigner.keyId}');
  print('  - Signature scheme: ${didPeerSigner.signatureScheme}');

  print('\n=== Example Complete ===');

  // Warning for production use
  print('\n⚠️  WARNING: This example uses fixed seeds for demonstration.');
  print('In production, use secure random generation for keys and seeds.');
}
