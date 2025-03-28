import 'dart:typed_data';
// import 'did_document.dart';
// import '../key_pair/key_pair.dart';

abstract interface class Did {
  Future<String> getDid();
  // static Future<String> create(List<KeyPair> keyPairs);
  // static Future<DidDocument> resolve(String did);
  Future<String> getDidWithKeyId(); // should be removed
  Future<Uint8List> getPublicKey(); // should be removed
}

// TODO: create a common class for did document
