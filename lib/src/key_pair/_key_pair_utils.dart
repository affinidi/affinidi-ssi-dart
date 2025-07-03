import 'dart:typed_data';
import './_encryption_utils.dart';

/// The encryption utility instance.
final encryptionUtils = EncryptionUtils();

/// Generates a valid private key.
T generateValidPrivateKey<T>(
  T Function() generate, {
  int maxAttempts = 3,
  int? expectedLength,
}) {
  for (var attempt = 0; attempt < maxAttempts; attempt++) {
    final privateKey = generate();
    final publicKey = (privateKey as dynamic).publicKey;

    final keXBytes = _bigIntToBytes(publicKey.X as BigInt);
    final keYBytes = _bigIntToBytes(publicKey.Y as BigInt);

    final len = expectedLength ?? keXBytes.length;
    if (keXBytes.length == len && keYBytes.length == len) {
      return privateKey;
    }
  }

  throw Exception(
      'Failed to generate valid private key after $maxAttempts attempts');
}

/// Converts a [BigInt] to bytes.
Uint8List _bigIntToBytes(BigInt value) {
  return value.isNegative
      ? encryptionUtils.intToBytes(value)
      : encryptionUtils.unsignedIntToBytes(value);
}
