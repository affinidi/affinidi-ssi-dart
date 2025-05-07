import 'dart:typed_data';

import 'package:ssi/src/wallet/key_store/in_memory_key_store.dart';
import 'package:ssi/ssi.dart';

/// Initialize a DID signer from seed
Future<DidSigner> initSigner(Uint8List seed) async {
  final keyStore = InMemoryKeyStore();
  final wallet = await Bip32Wallet.fromSeed(seed, keyStore);
  final key = await wallet.deriveKey(derivationPath: "m/44'/60'/0'/0'/0'");
  final doc = DidKey.generateDocument(key.publicKey);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: doc.verificationMethod[0].id,
    keyPair: key,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}
