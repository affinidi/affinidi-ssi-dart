import 'dart:typed_data';

import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';

Future<DidSigner> initSigner(Uint8List seed) async {
  final keyStore = InMemoryKeyStore();
  final wallet = await Bip32Wallet.fromSeed(seed, keyStore);
  final publicKey =
      await wallet.generateKey(derivationPath: "m/44'/60'/0'/0'/0'");
  final doc = DidKey.generateDocument(publicKey);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: doc.verificationMethod[0].id,
    wallet: wallet,
    walletKeyId: publicKey.id,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}
