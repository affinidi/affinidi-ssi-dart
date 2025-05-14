import 'dart:convert';
import 'dart:typed_data';

import 'package:ssi/ssi.dart';

Future<DidSigner> initSigner(Uint8List seed) async {
  final wallet = Bip32Wallet.fromSeed(seed);
  final key = await wallet.generateKey(keyId: "m/44'/60'/0'/0'/0'");
  final doc = DidKey.generateDocument(key.publicKey);

  final signer = DidSigner(
    didDocument: doc,
    didKeyId: doc.verificationMethod[0].id,
    keyPair: key,
    signatureScheme: SignatureScheme.ecdsa_secp256k1_sha256,
  );
  return signer;
}

final Map<String, dynamic> userProfile = jsonDecode(r'''
{"@context":{"UserProfile":{"@id":"https://schema.affinidi.com/UserProfileV1-0.jsonld","@context":{"@version":1.1,"@protected":true}},"Fname":{"@id":"schema-id:Fname","@type":"https://schema.org/Text"},"Lname":{"@id":"schema-id:Lname","@type":"https://schema.org/Text"},"Age":{"@id":"schema-id:Age","@type":"https://schema.org/Text"},"Address":{"@id":"schema-id:Address","@type":"https://schema.org/Text"}}}
''') as Map<String, dynamic>;

Future<Map<String, dynamic>?> testLoadDocument(Uri url) {
  if (url.toString() == 'https://schema.affinidi.com/UserProfileV1-0.jsonld') {
    return Future.value(userProfile);
  }
  return Future.value(null);
}

DateTime getNow() {
  return DateTime.parse('2025-04-25');
}

DateTime getPast() {
  return getNow().subtract(const Duration(days: 400));
}

DateTime getFuture() {
  return getNow().add(const Duration(days: 400));
}
