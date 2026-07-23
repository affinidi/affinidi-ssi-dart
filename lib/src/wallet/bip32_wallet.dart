import 'dart:typed_data';

import 'package:bip32_plus/bip32_plus.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../key_pair/secp256k1_key_pair.dart';
import '../types.dart';
import 'wallet.dart';

/// A wallet implementation that supports BIP32 key derivation with secp256k1 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It can optionally use a [IdToPathTransformer] to convert arbitrary
/// string key identifiers into full BIP32 derivation paths (e.g., "m/44'/60'/0'/0/0").
/// If no transformer is provided, the keyId itself is assumed to be the derivation path.
class Bip32Wallet implements Wallet {
  // Runtime cache for derived KeyPair objects, keyed by user-provided keyId
  final Map<String, Secp256k1KeyPair> _runtimeCache = {};
  // Root node derived from seed and used for BIP32 derivation
  final BIP32 _rootNode;
  // Transformer function to convert a string keyId to a full derivation path string
  final IdToPathTransformer keyIdToDerivationPathTransformer;

  /// Creates a new [Bip32Wallet] instance.
  /// Use the factory constructor `fromSeed` for typical instantiation.
  Bip32Wallet._(
    this._rootNode,
    this.keyIdToDerivationPathTransformer,
  );

  /// Creates a new [Bip32Wallet] using the provided seed and an ID-to-path transformer.
  ///
  /// [seed] - The master seed bytes. Must be 16, 32, or 64 bytes.
  /// [idToPathTransformer] - A function to convert a string ID
  ///                         into a full derivation path string (must start with "m/").
  static Bip32Wallet fromSeed({
    required Uint8List seed,
    required IdToPathTransformer idToPathTransformer,
  }) {
    if (seed.length != 16 && seed.length != 32 && seed.length != 64) {
      throw ArgumentError('BIP32 seed length must be 16, 32, or 64 bytes.');
    }

    final rootNode = BIP32.fromSeed(seed);
    return Bip32Wallet._(
      rootNode,
      idToPathTransformer,
    );
  }

  @override
  Future<List<SignatureScheme>> getSupportedSignatureSchemes(
      String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.supportedSignatureSchemes;
  }

  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.sign(data, signatureScheme: signatureScheme);
  }

  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.verify(
      data,
      signature,
      signatureScheme: signatureScheme,
    );
  }

  @override
  Future<KeyPair> generateKey({String? keyId, KeyType? keyType}) async {
    if (keyId == null) {
      throw ArgumentError(
          'keyId is required for Bip32Wallet to derive the specific key.');
    }

    final effectiveKeyType = keyType ?? KeyType.secp256k1;

    if (effectiveKeyType != KeyType.secp256k1) {
      throw SsiException(
        message:
            'Invalid keyType specified. Bip32Wallet only generates secp256k1 keys. Requested: $keyType',
        code: SsiExceptionType.invalidKeyType.code,
      );
    }

    return await _getKeyPair(keyId);
  }

  @override
  Future<PublicKey> getPublicKey(String keyId) async {
    final keyPair = await _getKeyPair(keyId);
    final keyData = keyPair.publicKey;
    return PublicKey(keyData.id, keyData.bytes, keyData.type);
  }

  @override
  Future<Uint8List> encrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.encrypt(data, publicKey: publicKey);
  }

  @override
  Future<Uint8List> decrypt(
    Uint8List data, {
    required String keyId,
    Uint8List? publicKey,
  }) async {
    final keyPair = await _getKeyPair(keyId);
    return keyPair.decrypt(data, publicKey: publicKey);
  }

  Future<Secp256k1KeyPair> _getKeyPair(String keyId) async {
    if (_runtimeCache.containsKey(keyId)) {
      return _runtimeCache[keyId]!;
    }

    final String fullPath = await keyIdToDerivationPathTransformer(keyId);

    if (!fullPath.startsWith('m/')) {
      throw ArgumentError(
          'The derivation path from keyIdToDerivationPathTransformer must start with "m/". Received: "$fullPath" for keyId: "$keyId"');
    }

    // Path validation (format, range for indices) is implicitly handled by derivePath.
    // For example, derivePath will throw if path is malformed.
    final derivedNode = _rootNode.derivePath(fullPath);
    // The Secp256k1KeyPair's 'id' is the user-facing keyId, not the fullPath.
    final keyPair = Secp256k1KeyPair(node: derivedNode, id: keyId);

    _runtimeCache[keyId] = keyPair;
    return keyPair;
  }

  /// Clears the runtime cache.
  void clearCache() {
    _runtimeCache.clear();
  }
}

/// An optional function that transforms a string identifier (keyId) into a full BIP32
/// derivation path string.
///
/// The returned string MUST be a full derivation path starting with "m/"
/// (e.g., "m/44'/60'/0'/0/0").
typedef IdToPathTransformer = Future<String> Function(String id);
