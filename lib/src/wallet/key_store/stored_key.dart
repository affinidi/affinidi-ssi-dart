import 'dart:typed_data';

import '../../types.dart';

/// Represents a key stored in the KeyStore.
class StoredKey {
  /// The type of the key (e.g., 'p256', 'ed25519').
  final KeyType type;

  /// The private key bytes.
  final Uint8List key;

  /// Creates a StoredKey instance.
  StoredKey({required this.type, required this.key});
}
