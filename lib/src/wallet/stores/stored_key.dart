import 'dart:typed_data';
import '../../types.dart';

/// Represents information about a key stored in the KeyStore.
class StoredKey {
  /// The cryptographic type of the key (e.g., p256, ed25519).
  final KeyType keyType;

  /// The private key bytes.
  final Uint8List privateKeyBytes;

  /// Creates a StoredKey instance.
  StoredKey({required this.keyType, required this.privateKeyBytes});

  /// Creates a StoredKey from a JSON map (for persistence).
  factory StoredKey.fromJson(Map<String, dynamic> json) {
    final keyType = KeyType.values.byName(json['keyType'] as String);

    final keyBytesList = (json['privateKeyBytes'] as List<dynamic>?)
        ?.map((e) => e as int)
        .toList();
    if (keyBytesList == null) {
      throw ArgumentError(
          'Missing privateKeyBytes for privateKeyBytes representation');
    }
    return StoredKey(
      keyType: keyType,
      privateKeyBytes: Uint8List.fromList(keyBytesList),
    );
  }

  /// Converts this StoredKey to a JSON map (for persistence).
  Map<String, dynamic> toJson() {
    return {
      'keyType': keyType.name,
      'privateKeyBytes': List<int>.from(privateKeyBytes),
    };
  }
}
