import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

/// Custom DidStore implementation that simulates persistence
class PersistentDidControllerStore extends DidStore {
  // In a real implementation, this would be backed by a database
  final Map<String, String> _storage = {};
  final Map<String, Map<String, dynamic>> _metadata = {};

  @override
  Future<void> setMapping(String didKeyId, String walletKeyId) async {
    _storage[didKeyId] = walletKeyId;
    _metadata[didKeyId] = {
      'createdAt': DateTime.now().toIso8601String(),
      'lastUsed': DateTime.now().toIso8601String(),
    };
    print('  ✓ Stored mapping: $didKeyId -> $walletKeyId');
  }

  @override
  Future<String?> getWalletKeyId(String didKeyId) async {
    final walletKeyId = _storage[didKeyId];
    if (walletKeyId != null) {
      _metadata[didKeyId]?['lastUsed'] = DateTime.now().toIso8601String();
    }
    return walletKeyId;
  }

  @override
  Future<void> removeMapping(String didKeyId) async {
    _storage.remove(didKeyId);
    _metadata.remove(didKeyId);
    print('  ✓ Removed mapping for: $didKeyId');
  }

  @override
  Future<void> clearAll() async {
    _storage.clear();
    _metadata.clear();
    print('  ✓ Cleared all mappings');
  }

  @override
  Future<List<String>> get verificationMethodIds async =>
      _storage.keys.toList();

  @override
  Future<List<String>> get authentication async => [];

  @override
  Future<List<String>> get keyAgreement async => [];

  @override
  Future<List<String>> get capabilityInvocation async => [];

  @override
  Future<List<String>> get capabilityDelegation async => [];

  @override
  Future<List<String>> get assertionMethod async => [];

  @override
  Future<List<ServiceEndpoint>> get serviceEndpoints async => [];

  @override
  Future<void> addAuthentication(String verificationMethodId) async {}

  @override
  Future<void> removeAuthentication(String verificationMethodId) async {}

  @override
  Future<void> addKeyAgreement(String verificationMethodId) async {}

  @override
  Future<void> removeKeyAgreement(String verificationMethodId) async {}

  @override
  Future<void> addCapabilityInvocation(String verificationMethodId) async {}

  @override
  Future<void> removeCapabilityInvocation(String verificationMethodId) async {}

  @override
  Future<void> addCapabilityDelegation(String verificationMethodId) async {}

  @override
  Future<void> removeCapabilityDelegation(String verificationMethodId) async {}

  @override
  Future<void> addAssertionMethod(String verificationMethodId) async {}

  @override
  Future<void> removeAssertionMethod(String verificationMethodId) async {}

  @override
  Future<void> addServiceEndpoint(ServiceEndpoint endpoint) async {}

  @override
  Future<void> removeServiceEndpoint(String id) async {}

  @override
  Future<void> clearVerificationMethodReferences() async {}

  @override
  Future<void> clearServiceEndpoints() async {}

  // Additional methods for advanced features
  Map<String, dynamic>? getMetadata(String didKeyId) => _metadata[didKeyId];

  void printStorageInfo() {
    print('\n📊 Storage Information:');
    print('Total mappings: ${_storage.length}');
    for (final entry in _storage.entries) {
      final meta = _metadata[entry.key];
      print('  - ${entry.key}');
      print('    Wallet Key: ${entry.value}');
      print('    Created: ${meta?['createdAt']}');
      print('    Last Used: ${meta?['lastUsed']}');
    }
  }
}

void main() async {
  print('=== DID Controller Advanced Example ===\n');

  // Initialize components
  // Use a different seed for the advanced example
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);

  // Use custom persistent store
  final persistentStore = PersistentDidControllerStore();

  // 1. Multiple verification methods with different purposes
  print(
      '1. Creating did:peer controller with multiple verification methods...\n');

  final peerController = DidPeerController(
    store: persistentStore,
    wallet: wallet,
  );

  // Generate keys for different purposes
  final authKey1 = await wallet.generateKey(
    keyId: 'auth-primary',
    keyType: KeyType.ed25519,
  );
  final authKey2 = await wallet.generateKey(
    keyId: 'auth-backup',
    keyType: KeyType.p256,
  );
  final keyAgreementKey = await wallet.generateKey(
    keyId: 'key-agreement',
    keyType: KeyType.p256,
  );
  final assertionKey = await wallet.generateKey(
    keyId: 'assertion',
    keyType: KeyType.ed25519,
  );

  print('Generated keys:');
  print('  - Primary Auth (ED25519): ${authKey1.id}');
  print('  - Backup Auth (P256): ${authKey2.id}');
  print('  - Key Agreement (P256): ${keyAgreementKey.id}');
  print('  - Assertion (ED25519): ${assertionKey.id}');

  // Add keys as verification methods and then add to different purposes
  final authVmId1 = await peerController.addVerificationMethod(authKey1.id);
  final authVmId2 = await peerController.addVerificationMethod(authKey2.id);
  final kaVmId = await peerController.addVerificationMethod(keyAgreementKey.id);
  final assertVmId =
      await peerController.addVerificationMethod(assertionKey.id);

  await peerController.addAuthentication(authVmId1);
  await peerController.addAuthentication(authVmId2);
  await peerController.addKeyAgreement(kaVmId);
  await peerController.addAssertionMethod(assertVmId);
  await peerController.addCapabilityInvocation(authVmId1);

  // 2. Service endpoints
  print('\n2. Adding service endpoints...\n');

  final serviceEndpoint = const MapEndpoint({
    'uri': 'https://example.com/didcomm',
    'accept': ['didcomm/v2', 'application/json'],
    'routingKeys': ['did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'],
  });

  await peerController.addServiceEndpoint(serviceEndpoint);
  print('Added DIDComm service endpoint');

  // Create the document
  final peerDocument = await peerController.getDidDocument();
  print('\nCreated did:peer DID: ${peerDocument.id}');
  print(
      'Total verification methods: ${peerDocument.verificationMethod.length}');
  print('Service endpoints: ${peerDocument.service.length}');

  // 3. Key purpose management
  print('\n3. Demonstrating key purpose management...\n');

  // Mappings are already set up by addVerificationMethod calls above

  // Verification method IDs are already available from above

  print('Verification method IDs:');
  print('  - Primary Auth: $authVmId1');
  print('  - Backup Auth: $authVmId2');
  print('  - Key Agreement: $kaVmId');
  print('  - Assertion: $assertVmId');

  // 4. Sign with different keys
  print('\n4. Signing with different keys...\n');

  final message = 'Important document'.codeUnits;

  // Sign with primary auth key
  final primarySignature = await peerController.sign(message, authVmId1);
  print(
      'Primary auth signature: ${hexEncode(primarySignature.sublist(0, 8))}...');

  // Sign with backup auth key
  final backupSignature = await peerController.sign(message, authVmId2);
  print(
      'Backup auth signature: ${hexEncode(backupSignature.sublist(0, 8))}...');

  // Verify both signatures
  final primaryValid =
      await peerController.verify(message, primarySignature, authVmId1);
  final backupValid =
      await peerController.verify(message, backupSignature, authVmId2);
  print('\nPrimary signature valid: $primaryValid');
  print('Backup signature valid: $backupValid');

  // 5. Advanced verification method management
  print('\n5. Advanced verification method management...\n');

  // Add a new key dynamically
  final newKey = await wallet.generateKey(
    keyId: 'new-capability-key',
    keyType: KeyType.secp256k1,
  );

  final newVmId = await peerController.addVerificationMethod(newKey.id);
  await peerController.addCapabilityDelegation(newVmId);

  print('Added new capability delegation key');
  print('New verification method ID: $newVmId');

  // Update document to reflect changes
  final updatedDocument = await peerController.getDidDocument();
  print(
      'Updated verification methods: ${updatedDocument.verificationMethod.length}');
  print(
      'Capability delegation methods: ${updatedDocument.capabilityDelegation.length}');

  // 6. Custom DiDControllerStore features
  print('\n6. Using custom store features...\n');

  persistentStore.printStorageInfo();

  // Get metadata for a specific mapping
  final metadata = persistentStore.getMetadata(authVmId1);
  print('\nMetadata for primary auth key:');
  print('  Created: ${metadata?['createdAt']}');
  print('  Last used: ${metadata?['lastUsed']}');

  // 7. Creating a DID Signer for credential operations
  print('\n7. Creating DID Signer for credentials...\n');

  final signer = await peerController.getSigner(
    assertVmId,
    signatureScheme: SignatureScheme.eddsa_sha512,
  );

  print('Created signer for assertion:');
  // DID is available in the didDocument passed to create the signer
  print('  - Verification Method: ${signer.didKeyId}');
  print('  - Signature Scheme: ${signer.signatureScheme}');

  // Example: Sign a credential (simplified)
  print(
      '\nExample credential data prepared for signing with DID: ${peerDocument.id}');

  // 8. Key rotation scenario
  print('\n8. Simulating key rotation...\n');

  // Remove old auth key reference
  await peerController.removeAuthentication(authVmId2);
  print('Removed backup authentication key from verification relationships');

  // Add new rotated key
  final rotatedKey = await wallet.generateKey(
    keyId: 'auth-rotated',
    keyType: KeyType.ed25519,
  );

  final rotatedVmId = await peerController.addVerificationMethod(rotatedKey.id);
  await peerController.addAuthentication(rotatedVmId);

  print('Added new rotated authentication key: $rotatedVmId');

  final finalDocument = await peerController.getDidDocument();
  print(
      '\nFinal authentication methods: ${finalDocument.authentication.length}');

  print('\n=== Advanced Example Complete ===');

  print('\n💡 Key Takeaways:');
  print('- DID Controllers support multiple keys with different purposes');
  print('- Service endpoints enable communication protocols');
  print('- Custom stores can add persistence and metadata');
  print('- Keys can be dynamically added and removed');
  print('- Different signature schemes can be used per operation');

  print('\n⚠️  WARNING: This example uses simplified key management.');
  print('In production, implement proper key storage and rotation policies.');
}
