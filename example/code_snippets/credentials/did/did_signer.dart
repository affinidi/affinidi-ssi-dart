import 'dart:typed_data';

import 'package:ssi/ssi.dart';

/// Initialize a DID signer from seed
Future<DidSigner> initSigner(Uint8List seed) async {
  final wallet = Bip32Wallet.fromSeed(seed);
  final key = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'");
  final doc = DidKey.generateDocument(key.publicKey);

  final signer = DidSigner(
    did: doc.id,
    didKeyId: doc.verificationMethod[0].id,
    keyPair: key,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}
