import 'dart:convert';
import 'package:ssi/ssi.dart';

void main() async {
  // Use a pretty print encoder
  const jsonEncoder = JsonEncoder.withIndent('  ');

  // --- DID with only authentication and key agreement ---
  print('\n\n--- DID with only auth and key agreement ---');

  // 1. Create dependencies
  var keyStore = InMemoryKeyStore();
  var wallet = PersistentWallet(keyStore);
  var didStore = InMemoryDidStore();
  var didPeerController = DidPeerController(store: didStore, wallet: wallet);

  // 2. Generate a key
  print('\nGenerating key...');
  final ed25519Key = await wallet.generateKey(keyType: KeyType.ed25519);
  print('Ed25519 key generated: ${ed25519Key.id}');

  // 3. Add key with a custom set of relationships
  print('\nAdding key with only authentication and key agreement...');
  final addKeyResult1 = await didPeerController.addVerificationMethod(
    ed25519Key.id,
    relationships: {
      VerificationRelationship.authentication,
    },
  );

  print('Verification methods added and purposes assigned:');
  print(' - Primary VM ID: ${addKeyResult1.verificationMethodId}');
  print(
      ' - Authentication VM ID: ${addKeyResult1.relationships[VerificationRelationship.authentication]}');
  print(
      ' - Key Agreement VM ID: ${addKeyResult1.relationships[VerificationRelationship.keyAgreement]}');
  print(' - All assigned relationships: ${addKeyResult1.relationships.keys}');

  final ed25519Key2 = await wallet.generateKey(keyType: KeyType.ed25519);
  final addKeyResult2 = await didPeerController.addVerificationMethod(
    ed25519Key2.id,
    relationships: {
      VerificationRelationship.keyAgreement,
    },
  );

  print('Verification methods added and purposes assigned:');
  print(' - Primary VM ID: ${addKeyResult2.verificationMethodId}');
  print(
      ' - Authentication VM ID: ${addKeyResult2.relationships[VerificationRelationship.authentication]}');
  print(
      ' - Key Agreement VM ID: ${addKeyResult2.relationships[VerificationRelationship.keyAgreement]}');
  print(' - All assigned relationships: ${addKeyResult2.relationships.keys}');

  // 4. Get and print the DID Document
  print('\n--- Generated DID Document (Custom Relationships) ---');
  final didDocument = await didPeerController.getDidDocument();
  print(jsonEncoder.convert(didDocument.toJson()));
  print('\nDID: ${didDocument.id}');

  // 5. Resolve and compare
  final resolvedDidDoc = DidPeer.resolve(didDocument.id);
  print('DID resolved successfully.');

  print(jsonEncoder.convert(resolvedDidDoc.toJson()));

  final resolvedJson = jsonEncoder.convert(resolvedDidDoc.toJson());
  final originalJson = jsonEncoder.convert(didDocument.toJson());

  print(
      'Resolved DID Document content matches generated document: ${resolvedJson == originalJson}');
}
