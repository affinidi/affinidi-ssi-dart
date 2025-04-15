import 'dart:typed_data';

import '../types.dart';

abstract interface class KeyPair {
  Future<String> get id;

  List<SignatureScheme> get supportedSignatureSchemes;

  Future<Uint8List> get publicKey;

  Future<KeyType> get publicKeyType;

  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  });

  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  });

  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey});

  Future<Uint8List> decrypt(Uint8List data, {Uint8List? publicKey});
}
