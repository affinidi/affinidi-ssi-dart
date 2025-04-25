import 'dart:typed_data';
import './_encryption_utils.dart';

final encryptionUtils = EncryptionUtils();

T generateValidPrivateKey<T>(
  T Function() generate, {
  int maxAttempts = 3,
}) {
  for (var attempt = 0; attempt < maxAttempts; attempt++) {
    final privateKey = generate();
    final publicKey = (privateKey as dynamic).publicKey;

    final keXBytes = _bigIntToBytes(publicKey.X as BigInt);
    final keYBytes = _bigIntToBytes(publicKey.Y as BigInt);

    if (keXBytes.length == 32 && keYBytes.length == 32) {
      return privateKey;
    }
  }

  throw Exception(
      'Failed to generate valid private key after $maxAttempts attempts');
}

Uint8List _bigIntToBytes(BigInt value) {
  return value.isNegative
      ? encryptionUtils.intToBytes(value)
      : encryptionUtils.unsignedIntToBytes(value);
}
