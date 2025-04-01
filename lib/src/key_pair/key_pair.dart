import 'dart:typed_data';

import '../types.dart';

abstract interface class KeyPair {
  List<SignatureScheme> get supportedSignatureSchemes;

  Future<Uint8List> getPublicKey();

  Future<KeyType> getKeyType();

  Future<String> getKeyId();

  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  });

  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    SignatureScheme? signatureScheme,
  });
}
