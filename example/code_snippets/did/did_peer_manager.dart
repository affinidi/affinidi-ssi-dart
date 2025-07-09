import 'dart:convert';
import 'package:ssi/ssi.dart';

void main() async {
  // Use a pretty print encoder
  const jsonEncoder = JsonEncoder.withIndent('  ');

  print('\n--- DidPeerManager Operations ---');

  // 1. Create dependencies: Wallet and DID Store
  // WARNING: InMemoryKeyStore is not secure for production use.
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);
  final didStore = InMemoryDidStore();

  // 2. Create the DidPeerManager
  final didPeerManager = DidPeerManager(store: didStore, wallet: wallet);
  print('DidPeerManager created.');

  // 3. Generate a key for authentication and key agreement
  print('\nGenerating key...');
  final ed25519Key = await wallet.generateKey(keyType: KeyType.ed25519);
  print('Ed25519 key generated: ${ed25519Key.id}');

  // 4. Add key to the manager, which will set up verification methods
  // for default relationships (authentication, key agreement, etc.)
  print('\nAdding key to manager...');
  final addKeyResult =
      await didPeerManager.addVerificationMethod(ed25519Key.id);
  final relationshipMap = addKeyResult.relationships;

  print('Verification methods added and purposes assigned:');
  print(' - Primary VM ID: ${addKeyResult.verificationMethodId}');
  print(
      ' - Authentication VM ID: ${relationshipMap[VerificationRelationship.authentication]}');
  print(
      ' - Key Agreement VM ID: ${relationshipMap[VerificationRelationship.keyAgreement]}');
  print(
      ' - Assertion Method VM ID: ${relationshipMap[VerificationRelationship.assertionMethod]}');
  print(
      ' - Capability Invocation VM ID: ${relationshipMap[VerificationRelationship.capabilityInvocation]}');
  print(
      ' - Capability Delegation VM ID: ${relationshipMap[VerificationRelationship.capabilityDelegation]}');

  // 5. Add a service endpoint
  print('\nAdding a service endpoint...');
  final serviceEndpoint = ServiceEndpoint(
    id: '#service-1', // ID is a fragment relative to the DID
    type: 'LinkedDomains',
    serviceEndpoint: const StringEndpoint('https://example.com/'),
  );
  await didPeerManager.addServiceEndpoint(serviceEndpoint);
  print('Service endpoint added.');

  // 7. Get and print the DID Document
  print('\n--- Generated DID Document (did:peer) ---');
  final didDocument = await didPeerManager.getDidDocument();
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
