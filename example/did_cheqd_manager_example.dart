import 'package:affinidi_ssi_dart/affinidi_ssi_dart.dart';

/// Example of how to use DidCheqdManager for did:cheqd operations.
Future<void> main() async {
  // Create a wallet and store
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);
  final store = InMemoryDidStore();
  
  // Create the DID manager
  final manager = DidCheqdManager(store: store, wallet: wallet);
  await manager.init();

  try {
    // Generate a key pair in the wallet
    final keyPair = await wallet.generateKey(
      keyId: 'cheqd-key',
      keyType: KeyType.ed25519,
    );

    // Add verification method with authentication relationship
    final result = await manager.addVerificationMethod(
      keyPair,
      relationships: {VerificationRelationship.authentication},
    );

    print('Added verification method: ${result.verificationMethodId}');

    // Register the DID on Cheqd network using the wallet's keys
    // The wallet keeps private keys secure and handles signing internally
    final did = await manager.registerDid(
      keyPair.id, // Use the key ID from the wallet
      network: 'testnet', // or 'mainnet'
    );

    print('Registered DID: $did');

    // Get the DID document
    final didDocument = await manager.getDidDocument();
    print('DID Document: ${didDocument.toJson()}');

  } catch (e) {
    print('Error: $e');
  }
}
