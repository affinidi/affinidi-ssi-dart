import 'dart:typed_data';

import '../types.dart';

/// Represents a base key with its type and public key bytes.
class PublicKey {
  /// Identifier of the key
  String keyId;

  /// The type of the key e.g., Ed25519
  KeyType keyType;

  /// The public key bytes
  Uint8List bytes;

  /// Creates a new [PublicKey] instance.
  ///
  /// [keyId] - The identifier of the key as [String].
  /// [bytes] - The public key bytes.
  /// [keyType] - The type of the key as [KeyType].
  PublicKey(
    this.keyId,
    this.bytes,
    this.keyType,
  );
}
