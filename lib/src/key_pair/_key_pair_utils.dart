import 'dart:typed_data';
import './_encryption_utils.dart';

/// The encryption utility instance.
final encryptionUtils = EncryptionUtils();

/// Converts a [BigInt] to bytes.
Uint8List _bigIntToBytes(BigInt value) {
  return value.isNegative
      ? encryptionUtils.intToBytes(value)
      : encryptionUtils.unsignedIntToBytes(value);
}
