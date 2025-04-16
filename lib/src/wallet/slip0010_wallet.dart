import 'dart:typed_data';

import '../key_pair/public_key.dart';
import '../types.dart';
import 'wallet.dart';

// TODO(FTL-20739): Implement SLIP-0010 wallet

class Slip0010Wallet implements Wallet {
  @override
  Future<bool> hasKey(String keyId) {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
    SignatureScheme? signatureScheme,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(String keyId) {
    throw UnimplementedError();
  }

  @override
  Future<PublicKey> generateKey({String? keyId, KeyType? keyType}) {
    throw UnimplementedError();
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) {
    throw UnimplementedError();
  }
}
