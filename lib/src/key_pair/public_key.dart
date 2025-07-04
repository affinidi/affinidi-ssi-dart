import 'dart:typed_data';

import '../types.dart';

/// Represents a base key with its type and public key bytes.
class PublicKey {
  /// Identifier of the key
  ///
  /// This identifier comes from the KeyPair and is NOT the same as a DID
  /// verification method ID. For DID operations, use DidKeyPair which
  /// properly manages the relationship between wallet key IDs and DID
  /// verification method IDs.
  String id;

  /// The type of the key e.g., Ed25519
  KeyType type;

  /// The public key bytes
  Uint8List bytes;

  /// Creates a new [PublicKey] instance.
  ///
  /// [id] - The identifier of the key as [String].
  /// [bytes] - The public key bytes.
  /// [type] - The type of the key as [KeyType].
  PublicKey(
    this.id,
    this.bytes,
    this.type,
  );
}
