import 'dart:typed_data';
import '../../types.dart';

/// Enum to distinguish how the key is stored.
enum StoredKeyRepresentation {
  /// The key is stored as raw private key bytes.
  privateKeyBytes,

  /// The key is stored as a derivation path.
  derivationPath,
}

/// Represents information about a key stored in the KeyStore.
/// Can hold either direct private key bytes or a derivation path.
class StoredKey {
  /// How the key is represented in storage.
  final StoredKeyRepresentation representation;

  /// The cryptographic type of the key (e.g., p256, ed25519).
  final KeyType keyType;

  /// The private key bytes (only if representation is privateKeyBytes).
  final Uint8List? privateKeyBytes;

  /// The derivation path string (only if representation is derivationPath).
  final String? derivationPath;

  /// Creates a StoredKey instance for raw private key bytes.
  StoredKey.fromPrivateKey({
    required this.keyType,
    required Uint8List keyBytes,
  })  : representation = StoredKeyRepresentation.privateKeyBytes,
        privateKeyBytes = keyBytes,
        derivationPath = null;

  /// Creates a StoredKey instance for a derivation path.
  StoredKey.fromDerivationPath({
    required this.keyType,
    required String path,
  })  : representation = StoredKeyRepresentation.derivationPath,
        privateKeyBytes = null,
        derivationPath = path;

  /// Creates a StoredKey from a JSON map (for persistence).
  factory StoredKey.fromJson(Map<String, dynamic> json) {
    final representation =
        StoredKeyRepresentation.values.byName(json['representation'] as String);
    final keyType = KeyType.values.byName(json['keyType'] as String);

    if (representation == StoredKeyRepresentation.privateKeyBytes) {
      final keyBytesList = (json['privateKeyBytes'] as List<dynamic>?)
          ?.map((e) => e as int)
          .toList();
      if (keyBytesList == null) {
        throw ArgumentError(
            'Missing privateKeyBytes for privateKeyBytes representation');
      }
      return StoredKey.fromPrivateKey(
        keyType: keyType,
        keyBytes: Uint8List.fromList(keyBytesList),
      );
    } else if (representation == StoredKeyRepresentation.derivationPath) {
      final path = json['derivationPath'] as String?;
      if (path == null) {
        throw ArgumentError(
            'Missing derivationPath for derivationPath representation');
      }
      return StoredKey.fromDerivationPath(
        keyType: keyType,
        path: path,
      );
    } else {
      throw ArgumentError('Invalid StoredKey representation in JSON');
    }
  }

  /// Converts this StoredKey to a JSON map (for persistence).
  Map<String, dynamic> toJson() {
    return {
      'representation': representation.name,
      'keyType': keyType.name,
      if (privateKeyBytes != null)
        'privateKeyBytes': List<int>.from(privateKeyBytes!),
      if (derivationPath != null) 'derivationPath': derivationPath,
    };
  }
}
