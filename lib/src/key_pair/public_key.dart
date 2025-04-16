import 'dart:typed_data';

import '../types.dart';

/// Represents a base key with its type and public key bytes.
class PublicKey {
  /// The type of the key e.g., Ed25519
  KeyType type;

  /// The public key bytes
  Uint8List bytes;

  /// Creates a new [PublicKey] instance.
  ///
  /// [bytes] - The public key bytes.
  /// [type] - The type of the key.
  PublicKey(
    this.bytes,
    this.type,
  );
}
