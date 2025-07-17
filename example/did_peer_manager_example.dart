import 'dart:convert';
import 'dart:typed_data';
import 'package:ssi/ssi.dart';
import 'package:ssi/src/did/stores/in_memory_did_store.dart';

import 'utility.dart';

Future<void> main() async {
  // Create a wallet for key management
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);

  // Create separate stores for key mapping and document references
  final keyMappingStore = InMemoryDidKeyMappingStore();
  final documentReferenceStore = InMemoryDidDocumentReferenceStore();

  // Create a DID Peer manager
  final manager = DidPeerManager(
    keyMappingStore: keyMappingStore,
    documentReferenceStore: documentReferenceStore,
    wallet: wallet,
  );

  // Generate authentication and key agreement keys
  final authKeyId = 'auth-key-1';
  final agreementKeyId = 'agreement-key-1';

  final authKey = await wallet.generateKey(keyId: authKeyId);
  final agreementKey = await wallet.generateKey(keyId: agreementKeyId);

  // Add verification methods
  final authVerificationMethodId =
      await manager.addVerificationMethod(authKey.id);
  final agreementVerificationMethodId =
      await manager.addVerificationMethod(agreementKey.id);

  // Set up verification method purposes
  await manager
      .addAuthentication(authVerificationMethodId.verificationMethodId);
  await manager
      .addKeyAgreement(agreementVerificationMethodId.verificationMethodId);

  // Add service endpoints
  final serviceEndpoint = ServiceEndpoint(
    id: '#service-1',
    type: 'MessagingService',
    serviceEndpoint: const StringEndpoint('https://example.com/messaging'),
  );
  await manager.addServiceEndpoint(serviceEndpoint);

  // Get the DID document
  final didDocument = await manager.getDidDocument();
  print('DID: ${didDocument.id}');
  print(
      'Verification methods amount: ${didDocument.verificationMethod.length}');
  for (var vm in didDocument.verificationMethod) {
    printJsonFrom(vm);
  }
  print('Authentication methods amount: ${didDocument.authentication.length}');
  for (var auth in didDocument.authentication) {
    printJsonFrom(auth);
  }
  print('Key agreement methods amount: ${didDocument.keyAgreement.length}');

  for (var ka in didDocument.keyAgreement) {
    printJsonFrom(ka);
  }
  print('Service endpoints amount: ${didDocument.service.length}');

  for (var service in didDocument.service) {
    printJsonFrom(service);
  }

  // Example: Add multiple authentication keys
  final authKey2Id = 'auth-key-2';
  final authKey2 = await wallet.generateKey(keyId: authKey2Id);
  final authVerificationMethod2Id =
      await manager.addVerificationMethod(authKey2.id);
  await manager
      .addAuthentication(authVerificationMethod2Id.verificationMethodId);

  // Sign data using authentication key
  final dataToSign = Uint8List.fromList('Hello, DID Peer!'.codeUnits);
  final signature = await manager.sign(
      dataToSign, authVerificationMethodId.verificationMethodId);
  print('\nSigned data with authentication key');
  print('Signature: ${base64.encode(signature)}');

  // Verify the signature
  final isValid = await manager.verify(
    dataToSign,
    signature,
    authVerificationMethodId.verificationMethodId,
  );
  print('Signature valid: $isValid');

  // Get updated DID document with multiple keys
  final updatedDocument = await manager.getDidDocument();
  print('\nUpdated DID document:');
  print(
      'Total verification methods: ${updatedDocument.verificationMethod.length}');
  print('Authentication methods: ${updatedDocument.authentication.length}');
}
