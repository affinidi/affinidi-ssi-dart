import 'dart:typed_data';

import 'package:ssi/ssi.dart';

Future<DidSigner> initSigner(Uint8List seed) async {
  final wallet = Bip32Wallet.fromSeed(seed);
  final keyPair = await wallet.createKeyPair("0-0");
  final doc = await DidKey.create([keyPair]);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: doc.verificationMethod[0].id,
    keyPair: keyPair,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}
