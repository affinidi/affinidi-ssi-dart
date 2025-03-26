import 'dart:typed_data';

import 'did.dart';

// TODO: DID web
class DidWeb implements Did {
  Future<String> getDid() {
    throw UnimplementedError();
  }

  Future<String> getDidWithKeyId() {
    throw UnimplementedError();
  }

  Future<Uint8List> getPublicKey() {
    throw UnimplementedError();
  }
}
