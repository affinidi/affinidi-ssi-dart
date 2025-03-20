import 'dart:typed_data';

import '../types.dart';

// TODO: DID peer
class DidWeb {
  static Future<String> getDid(Uint8List publicKey,
      {KeyType keyType = KeyType.secp256k1}) async {
    throw UnimplementedError();
  }

  static Uint8List getPublicKey(String didKey) {
    throw UnimplementedError();
  }
}
