import 'dart:convert';
import 'package:ssi/ssi.dart';

import '../../utility.dart';

void main() async {
  // --- DID with only authentication and key agreement ---
  print('\n\n--- DID with only auth and key agreement ---');

  // 1. Create dependencies
  var keyStore = InMemoryKeyStore();
  var wallet = PersistentWallet(keyStore);
  var didPeerManager = DidPeerManager(
    keyMappingStore: InMemoryDidKeyMappingStore(),
    documentReferenceStore: InMemoryDidDocumentReferenceStore(),
    wallet: wallet,
  );

  // 2. Generate a key
  print('\nGenerating key...');
  final ed25519Key = await wallet.generateKey(keyType: KeyType.ed25519);
  print('Ed25519 key generated: ${ed25519Key.id}');

  // 3. Add key with a custom set of relationships
  print('\nAdding key with only authentication and key agreement...');
  final addKeyResult1 = await didPeerManager.addVerificationMethod(
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
  final addKeyResult2 = await didPeerManager.addVerificationMethod(
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
  final didDocument = await didPeerManager.getDidDocument();
  printJsonFrom(didDocument);
  print('\nDID: ${didDocument.id}');

  // 5. Resolve and compare
  final resolvedDidDoc = DidPeer.resolve(didDocument.id);
  print('DID resolved successfully.');

  printJsonFrom(resolvedDidDoc);

  final resolvedJson = resolvedDidDoc.toJson();
  final originalJson = didDocument.toJson();

  print(
      'Resolved DID Document content matches generated document: ${resolvedJson == originalJson}');
}
