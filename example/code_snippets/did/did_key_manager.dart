import 'dart:convert';
import 'package:ssi/ssi.dart';

void main() async {
  // Use a pretty print encoder
  const jsonEncoder = JsonEncoder.withIndent('  ');

  print('\n--- DidKeyManager Operations ---');

  // 1. Create dependencies: Wallet and DID Store
  // WARNING: InMemoryKeyStore is not secure for production use.
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);
  final didStore = InMemoryDidStore();

  // 2. Create the DidKeyManager
  final didKeyManager = DidKeyManager(store: didStore, wallet: wallet);
  print('DidKeyManager created.');

  // 3. Generate a key in the wallet to be used for the DID
  print('\nGenerating a new Ed25519 key for the did:key...');
  final key = await wallet.generateKey(keyType: KeyType.ed25519);
  print('Key generated with ID: ${key.id}');

  // 4. Add the key to the manager. This associates the wallet key with the DID.
  await didKeyManager.addVerificationMethod(key.id);
  print('Verification method added to the manager.');

  // 5. Get and print the DID Document
  print('\n--- Generated DID Document ---');
  final didDocument = await didKeyManager.getDidDocument();
  print(jsonEncoder.convert(didDocument.toJson()));
  print('DID: ${didDocument.id}');

  // 6. Demonstrate did:key limitations
  print('\n--- Demonstrating did:key Limitations ---');

  // Attempt to add a second key (should fail)
  try {
    print('\nAttempting to add a second key...');
    final anotherKey = await wallet.generateKey(keyType: KeyType.ed25519);
    await didKeyManager.addVerificationMethod(anotherKey.id);
  } catch (e) {
    print('As expected, failed to add a second key.');
  }

  // Attempt to add a service endpoint (should fail)
  try {
    print('\nAttempting to add a service endpoint...');
    final serviceEndpoint = ServiceEndpoint(
      id: '${didDocument.id}#service-1',
      type: 'TestService',
      serviceEndpoint: const StringEndpoint('https://example.com/test'),
    );
    await didKeyManager.addServiceEndpoint(serviceEndpoint);
  } catch (e) {
    print('As expected, failed to add a service endpoint.');
  }
}
