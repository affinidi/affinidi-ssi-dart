import 'dart:typed_data';

abstract interface class Did {
  // TODO: update interface to support multi key did methods
  Future<String> getDid();
  Future<String> getDidWithKeyId();
  Future<Uint8List> getPublicKey();
}

// TODO: create a common class for did document
