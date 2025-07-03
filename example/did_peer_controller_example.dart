import 'dart:convert';
import 'dart:typed_data';
import 'package:ssi/ssi.dart';

Future<void> main() async {
  // Create a wallet for key management
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);

  // Create a storage for DID controller mappings
  final store = InMemoryDidStore();

  // Create a DID Peer controller
  final controller = DidPeerController(
    store: store,
    wallet: wallet,
  );

  // Generate authentication and key agreement keys
  final authKeyId = 'auth-key-1';
  final agreementKeyId = 'agreement-key-1';

  final authKey = await wallet.generateKey(keyId: authKeyId);
  final agreementKey = await wallet.generateKey(keyId: agreementKeyId);

  // Add verification methods
  final authVerificationMethodId =
      await controller.addVerificationMethod(authKey.id);
  final agreementVerificationMethodId =
      await controller.addVerificationMethod(agreementKey.id);

  // Set up verification method purposes
  await controller
      .addAuthentication(authVerificationMethodId.verificationMethodId);
  await controller
      .addKeyAgreement(agreementVerificationMethodId.verificationMethodId);

  // Add service endpoints
  final serviceEndpoint = ServiceEndpoint(
    id: '#service-1',
    type: 'MessagingService',
    serviceEndpoint: const StringEndpoint('https://example.com/messaging'),
  );
  await controller.addServiceEndpoint(serviceEndpoint);

  // Get the DID document
  final didDocument = await controller.getDidDocument();
  print('DID: ${didDocument.id}');
  print('Verification methods: ${didDocument.verificationMethod.length}');
  print('Authentication methods: ${didDocument.authentication.length}');
  print('Key agreement methods: ${didDocument.keyAgreement.length}');
  print('Service endpoints: ${didDocument.service.length}');

  // Example: Add multiple authentication keys
  final authKey2Id = 'auth-key-2';
  final authKey2 = await wallet.generateKey(keyId: authKey2Id);
  final authVerificationMethod2Id =
      await controller.addVerificationMethod(authKey2.id);
  await controller
      .addAuthentication(authVerificationMethod2Id.verificationMethodId);

  // Sign data using authentication key
  final dataToSign = Uint8List.fromList('Hello, DID Peer!'.codeUnits);
  final signature = await controller.sign(
      dataToSign, authVerificationMethodId.verificationMethodId);
  print('\nSigned data with authentication key');
  print('Signature: ${base64.encode(signature)}');

  // Verify the signature
  final isValid = await controller.verify(
    dataToSign,
    signature,
    authVerificationMethodId.verificationMethodId,
  );
  print('Signature valid: $isValid');

  // Get updated DID document with multiple keys
  final updatedDocument = await controller.getDidDocument();
  print('\nUpdated DID document:');
  print(
      'Total verification methods: ${updatedDocument.verificationMethod.length}');
  print('Authentication methods: ${updatedDocument.authentication.length}');
}
