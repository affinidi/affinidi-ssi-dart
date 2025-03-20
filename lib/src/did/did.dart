import 'dart:typed_data';

abstract interface class Did {
  // NOTE: do these need to be async?
  Future<String> getDid();
  Future<String> getDidWithKeyId();
  Future<Uint8List> getPublicKey();
}

// TODO: create a common class for did document
