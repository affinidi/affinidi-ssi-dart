import 'dart:convert';
import 'dart:typed_data';
import 'package:ssi/ssi.dart';

Future<void> main() async {
  // Create a wallet for key management
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);

  // Create a DID Key manager
  final manager = DidKeyManager(
    keyMappingStore: InMemoryDidKeyMappingStore(),
    documentReferenceStore: InMemoryDidDocumentReferenceStore(),
    wallet: wallet,
  );

  // Generate a new key in the wallet
  final walletKeyId = 'my-signing-key';
  final key = await wallet.generateKey(keyId: walletKeyId);
  print('Generated key with ID: $walletKeyId');

  // Add the key as a verification method to the DID manager
  final verificationMethodId = await manager.addVerificationMethod(key.id);
  print('Verification method ID: ${verificationMethodId.verificationMethodId}');

  // Get the DID document
  final didDocument = await manager.getDidDocument();
  print('DID: ${didDocument.id}');
  print('Verification methods: ${didDocument.verificationMethod.length}');

  // Sign data using the DID manager
  final dataToSign = Uint8List.fromList('Hello, DID Key!'.codeUnits);
  final signature =
      await manager.sign(dataToSign, verificationMethodId.verificationMethodId);
  print('Signature: ${base64.encode(signature)}');

  // Verify the signature
  final isValid = await manager.verify(
    dataToSign,
    signature,
    verificationMethodId.verificationMethodId,
  );
  print('Signature valid: $isValid');

  // Get a DID signer for credential operations
  final signer =
      await manager.getSigner(verificationMethodId.verificationMethodId);
  print('Signer DID Key ID: ${signer.keyId}');
}
