import 'dart:convert';
import 'dart:typed_data';
import 'package:ssi/ssi.dart';

Future<void> main() async {
  // Create a wallet for key management
  final keyStore = InMemoryKeyStore();
  final wallet = PersistentWallet(keyStore);

  // Create a storage for DID controller mappings
  final store = InMemoryDidStore();

  // Create a DID Key controller
  final controller = DidKeyController(
    store: store,
    wallet: wallet,
  );

  // Generate a new key in the wallet
  final walletKeyId = 'my-signing-key';
  final key = await wallet.generateKey(keyId: walletKeyId);
  print('Generated key with ID: $walletKeyId');

  // Add the key as a verification method to the DID controller
  final verificationMethodId = await controller.addVerificationMethod(key.id);
  print('Verification method ID: ${verificationMethodId.verificationMethodId}');

  // Get the DID document
  final didDocument = await controller.getDidDocument();
  print('DID: ${didDocument.id}');
  print('Verification methods: ${didDocument.verificationMethod.length}');

  // Sign data using the DID controller
  final dataToSign = Uint8List.fromList('Hello, DID Key!'.codeUnits);
  final signature = await controller.sign(
      dataToSign, verificationMethodId.verificationMethodId);
  print('Signature: ${base64.encode(signature)}');

  // Verify the signature
  final isValid = await controller.verify(
    dataToSign,
    signature,
    verificationMethodId.verificationMethodId,
  );
  print('Signature valid: $isValid');

  // Get a DID signer for credential operations
  final signer =
      await controller.getSigner(verificationMethodId.verificationMethodId);
  print('Signer DID Key ID: ${signer.didKeyId}');
}
