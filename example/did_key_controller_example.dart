import 'package:ssi/ssi.dart';

Future<void> main() async {
  // Create a wallet for key management
  final wallet = GenericBIP32Wallet.generate();

  // Create a storage for DID controller mappings
  final store = InMemoryDidStore();

  // Create a DID Key controller
  final controller = DidKeyController(
    store: store,
    wallet: wallet,
  );

  // Generate a new key in the wallet
  final walletKeyId = 'my-signing-key';
  final keyPair = await wallet.generateKey(keyId: walletKeyId);
  print('Generated key with ID: $walletKeyId');

  // Add the key as a verification method to the DID controller
  final verificationMethodId =
      await controller.addVerificationMethod(walletKeyId);
  print('Verification method ID: $verificationMethodId');

  // Get the DID document
  final didDocument = await controller.getDidDocument();
  print('DID: ${didDocument.id}');
  print('Verification methods: ${didDocument.verificationMethod.length}');

  // Sign data using the DID controller
  final dataToSign = 'Hello, DID Key!'.toBytes();
  final signature = await controller.sign(dataToSign, verificationMethodId);
  print('Signature: ${signature.toBase64()}');

  // Verify the signature
  final isValid = await controller.verify(
    dataToSign,
    signature,
    verificationMethodId,
  );
  print('Signature valid: $isValid');

  // Get a DID signer for credential operations
  final signer = await controller.getSigner(verificationMethodId);
  print('Signer DID: ${signer.did}');
}
