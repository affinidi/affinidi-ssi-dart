import 'dart:convert';
import 'package:ssi/ssi.dart';

void main() async {
  // Use a pretty print encoder
  const jsonEncoder = JsonEncoder.withIndent('  ');

  print('\n--- DidPeerController Operations ---');

  // 1. Create dependencies: Wallet and DID Store
  // WARNING: InMemoryKeyStore is not secure for production use.
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);
  final didStore = InMemoryDidStore();

  // 2. Create the DidPeerController
  final didPeerController = DidPeerController(store: didStore, wallet: wallet);
  print('DidPeerController created.');

  // 3. Generate keys for authentication and key agreement
  print('\nGenerating keys...');
  final ed25519Key =
      (await wallet.generateKey(keyType: KeyType.ed25519)) as Ed25519KeyPair;
  print('Ed25519 key generated: ${ed25519Key.id}');
  final x25519PublicKey = await ed25519Key.ed25519KeyToX25519PublicKey();
  print('X25519 key derived from Ed25519 key');

  // 4. Add keys as verification methods to the controller
  final authVerificationMethodId =
      await didPeerController.addVerificationMethod(ed25519Key.publicKey);
  final agreementVerificationMethodId =
      await didPeerController.addVerificationMethod(x25519PublicKey);
  print('Verification methods added:');
  print(' - Auth VM ID: $authVerificationMethodId');
  print(' - Agreement VM ID: $agreementVerificationMethodId');

  // 5. Assign verification methods to their purposes
  print('\nAssigning verification purposes...');
  await didPeerController.addAuthentication(authVerificationMethodId);
  await didPeerController.addKeyAgreement(agreementVerificationMethodId);
  print('Purposes assigned.');

  // 6. Add a service endpoint
  print('\nAdding a service endpoint...');
  final serviceEndpoint = ServiceEndpoint(
    id: '#service-1', // ID is a fragment relative to the DID
    type: 'LinkedDomains',
    serviceEndpoint: const StringEndpoint('https://example.com/'),
  );
  await didPeerController.addServiceEndpoint(serviceEndpoint);
  print('Service endpoint added.');

  // 7. Get and print the DID Document
  print('\n--- Generated DID Document (did:peer) ---');
  final didDocument = await didPeerController.getDidDocument();
  print(jsonEncoder.convert(didDocument.toJson()));
  print('\nDID: ${didDocument.id}');

  // 8. Verify the DID can be resolved from the document
  // This is a conceptual check; did:peer resolution from the long-form DID
  // involves parsing the DID string itself.
  print('\nResolving DID from the generated long-form DID string...');
  final resolvedDidDoc = DidPeer.resolve(didDocument.id);
  print('DID resolved successfully.');

  print(jsonEncoder.convert(resolvedDidDoc.toJson()));

  final resolvedJson = jsonEncoder.convert(resolvedDidDoc.toJson());
  final originalJson = jsonEncoder.convert(didDocument.toJson());

  // Note: The resolved document's DID will be the short-form version,
  // so we compare the rest of the content.
  print(
      'Resolved DID Document content matches generated document: ${resolvedJson == originalJson}');
}
