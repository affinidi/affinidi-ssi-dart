import 'dart:typed_data';

import 'package:base_codecs/base_codecs.dart';
import 'package:ssi/ssi.dart';

void main() async {
  print('=== DID Controller Basic Example ===\n');

  // Step 1: Create wallet
  print('1. Creating wallet...');
  final seed = hexDecode(
    'a1772b144344781f2a55fc4d5e49f3767bb0967205ad08454a09c76d96fd2ccd',
  );
  final wallet = Bip32Wallet.fromSeed(seed);
  print('Wallet created from seed.');

  // Step 2: Create DID Controller
  print('\n2. Creating DID Controllers...');

  // Create did:key controller
  print('\n--- did:key Controller ---');
  final keyMapping = DefaultDiDControllerStore();
  final didKeyController = DidKeyController(
    keyMapping: keyMapping,
    wallet: wallet,
  );

  // Generate a key for did:key
  final keyForDidKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'");
  print(
      'Generated key for did:key. Public key: ${keyForDidKey.publicKey.bytes.sublist(1, 9)}...');

  // Create DID document
  final didKeyDocument =
      await didKeyController.createDidDocumentFromKey(keyForDidKey.id);
  print('did:key DID: ${didKeyDocument.id}');
  print('Verification methods: ${didKeyDocument.verificationMethod.length}');

  // Create did:peer controller
  print('\n--- did:peer Controller ---');
  final didPeerController = DidPeerController(
    keyMapping: DefaultDiDControllerStore(),
    wallet: wallet,
  );

  // Generate keys for did:peer
  final authKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/1'");
  final keyAgreementKey = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/2'");
  print(
      'Generated authentication key. Public key: ${authKey.publicKey.bytes.sublist(1, 9)}...');
  print(
      'Generated key agreement key. Public key: ${keyAgreementKey.publicKey.bytes.sublist(1, 9)}...');

  // Create DID document with multiple keys
  final didPeerDocument = await didPeerController.createDidDocumentWithKeys(
    [authKey.id],
    [keyAgreementKey.id],
  );
  print('did:peer DID: ${didPeerDocument.id}');
  print('Verification methods: ${didPeerDocument.verificationMethod.length}');
  print('Authentication methods: ${didPeerDocument.authentication.length}');
  print('Key agreement methods: ${didPeerDocument.keyAgreement.length}');

  // Step 3: Sign and verify
  print('\n3. Signing and verifying data...');
  final data = Uint8List.fromList([1, 2, 3, 4, 5]);
  print('Data to sign: ${hexEncode(data)}');

  // Sign with did:key
  print('\n--- Signing with did:key ---');
  final didKeyVmId = didKeyDocument.verificationMethod[0].id;
  // Important: Set up the key mapping for did:key
  didKeyController.keyMapping.setMapping(didKeyVmId, keyForDidKey.id);

  final didKeySignature = await didKeyController.sign(data, didKeyVmId);
  print('Signature: ${didKeySignature.sublist(0, 8)}...');

  final didKeyVerified = await didKeyController.verify(
    data,
    didKeySignature,
    didKeyVmId,
  );
  print('Verification result: $didKeyVerified');

  // Sign with did:peer
  print('\n--- Signing with did:peer ---');
  // Find the verification method ID for the authentication key
  final didPeerVmId =
      await didPeerController.findVerificationMethodId(authKey.id);
  didPeerController.keyMapping.setMapping(didPeerVmId, authKey.id);

  final didPeerSignature = await didPeerController.sign(data, didPeerVmId);
  print('Signature: ${didPeerSignature.sublist(0, 8)}...');

  final didPeerVerified = await didPeerController.verify(
    data,
    didPeerSignature,
    didPeerVmId,
  );
  print('Verification result: $didPeerVerified');

  // Step 4: Get DID Signer for use with credentials
  print('\n4. Getting DID Signer for credential operations...');
  final didKeySigner = await didKeyController.getSigner(didKeyVmId);
  print('did:key signer created:');
  // DID is available in the didDocument passed to create the signer
  print('  - Key ID: ${didKeySigner.didKeyId}');
  print('  - Signature scheme: ${didKeySigner.signatureScheme}');

  final didPeerSigner = await didPeerController.getSigner(didPeerVmId);
  print('\ndid:peer signer created:');
  // DID is available in the didDocument passed to create the signer
  print('  - Key ID: ${didPeerSigner.didKeyId}');
  print('  - Signature scheme: ${didPeerSigner.signatureScheme}');

  print('\n=== Example Complete ===');

  // Warning for production use
  print('\n⚠️  WARNING: This example uses fixed seeds for demonstration.');
  print('In production, use secure random generation for keys and seeds.');
}
