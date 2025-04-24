import 'package:ssi/ssi.dart';
import 'dart:typed_data';

/// Initialize a DID signer from seed
Future<DidSigner> initSigner(Uint8List seed) async {
  final wallet = Bip32Wallet.fromSeed(seed);
  final publicKey = await wallet.getPublicKey(Bip32Wallet.rootKeyId);
  final doc = DidKey.generateDocument(publicKey);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: doc.verificationMethod[0].id,
    wallet: wallet,
    walletKeyId: Bip32Wallet.rootKeyId,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}
