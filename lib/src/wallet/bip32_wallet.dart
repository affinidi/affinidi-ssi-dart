import 'dart:typed_data';

import 'package:bip32/bip32.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/public_key.dart';
import '../key_pair/secp256k1_key_pair.dart';
import '../types.dart';
import 'key_store/key_store_interface.dart';
import 'wallet.dart';

/// A wallet implementation that supports BIP32 key derivation with secp256k1 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It supports signing and verifying messages using secp256k1 signature scheme.
class Bip32Wallet implements Wallet {
  /// The base derivation path.
  static const baseDerivationPath = "m/44'/60'/0'/0/0";

  /// The identifier for the root key pair.
  static const rootKeyId = "0-0";

  /// The map of key identifiers to key pairs.
  final Map<String, Secp256k1KeyPair> _keyMap;

  /// The BIP32 node of the root key pair.
  final BIP32 _rootNode;

  /// Creates a new [Bip32Wallet] instance with the given BIP32 node.
  ///
  /// [node] - The BIP32 node to use as the root node.
  Bip32Wallet._(BIP32 node)
      : _keyMap = {rootKeyId: Secp256k1KeyPair(node: node)},
        _rootNode = node;

  /// Creates a new [Bip32Wallet] instance from a seed.
  ///
  /// [seed] - The seed to use for key derivation.
  ///
  /// Returns a new [Bip32Wallet] instance.
  factory Bip32Wallet.fromSeed(Uint8List seed) {
    final rootNode = BIP32.fromSeed(seed);
    return Bip32Wallet._(rootNode);
  }

  /// Creates a new [Bip32Wallet] instance from a private key.
  ///
  /// [privateKey] - The private key to use.
  ///
  /// Returns a new [Bip32Wallet] instance.
  factory Bip32Wallet.fromPrivateKey(Uint8List privateKey) {
    // TODO: validate if chainCode is correct
    final chainCode = Uint8List(0);
    final rootNode = BIP32.fromPrivateKey(privateKey, chainCode);
    return Bip32Wallet._(rootNode);
  }

  /// Creates a new [Bip32Wallet] instance from a KeyStore by retrieving the seed.
  ///
  /// [keyStore] - The KeyStore to use to fetch the seed.
  ///
  /// Returns a [Future] that completes with the new [Bip32Wallet] instance.
  /// Throws [ArgumentError] if the seed is not found in the KeyStore.
  static Future<Bip32Wallet> createFromKeyStore(
    KeyStore keyStore,
  ) async {
    final storedSeed = await keyStore.getSeed();
    if (storedSeed == null) {
      throw ArgumentError(
          'Seed not found in KeyStore. Cannot create Bip32Wallet.');
    }
    return Bip32Wallet.fromSeed(storedSeed);
  }

  /// Checks if a key with the specified identifier exists in the wallet.
  ///
  /// [keyId] - The identifier of the key to check.
  ///
  /// Returns a [Future] that completes with `true` if the key exists,
  /// `false` otherwise.
  @override
  Future<bool> hasKey(String keyId) {
    return Future.value(_keyMap.containsKey(keyId));
  }

  /// Signs the provided data using the specified key.
  ///
  /// [data] - The data to be signed.
  /// [keyId] - The identifier of the key to use for signing.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with the signature as a [Uint8List].
  @override
  Future<Uint8List> sign(
    Uint8List data, {
    required String keyId,
    SignatureScheme? signatureScheme,
  }) {
    final keyPair = _getKeyPair(keyId);
    return keyPair.sign(data, signatureScheme: signatureScheme);
  }

  /// Verifies a signature using the specified key.
  ///
  /// [data] - The data that was signed.
  /// [signature] - The signature to verify.
  /// [keyId] - The identifier of the key to use for verification.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with `true` if the signature is valid,
  /// `false` otherwise.
  @override
  Future<bool> verify(
    Uint8List data, {
    required Uint8List signature,
    required String keyId,
    SignatureScheme? signatureScheme,
  }) {
    final keyPair = _getKeyPair(keyId);
    return keyPair.verify(
      data,
      signature,
      signatureScheme: signatureScheme,
    );
  }

  /// Creates a new key pair with the specified identifier.
  ///
  /// [keyId] - The identifier for the new key pair in the format `{accountNumber}-{accountKeyId}`.
  /// [keyType] - The type of key to create.
  ///
  /// Returns a [Future] that completes with the newly created [Secp256k1KeyPair].
  ///
  /// Throws an [SsiException] if:
  /// - Unsupported key type
  /// - The root key pair is missing
  @override
  Future<PublicKey> createKeyPair(String keyId, {KeyType? keyType}) async {
    if (keyType != null && keyType != KeyType.secp256k1) {
      throw SsiException(
        message: 'Only secp256k1 key type is supported for Bip32Wallet',
        code: SsiExceptionType.invalidKeyType.code,
      );
    }
    if (_keyMap.containsKey(keyId)) {
      return Future.value(_keyMap[keyId]!.publicKey);
    }
    if (!_keyMap.containsKey(rootKeyId)) {
      throw SsiException(
        message: 'Root key pair is missing.',
        code: SsiExceptionType.keyPairMissingPrivateKey.code,
      );
    }
    final (accountNumber, accountKeyId) = _validateKeyId(keyId);

    final derivationPath =
        _buildDerivationPath(baseDerivationPath, accountNumber, accountKeyId);
    final keyPair =
        Secp256k1KeyPair(node: _rootNode.derivePath(derivationPath));
    _keyMap[keyId] = keyPair;
    return Future.value(keyPair.publicKey);
  }

  /// Retrieves the public key for the specified key.
  ///
  /// [keyId] - The identifier of the key.
  ///
  /// Returns a [Future] that completes with the public key as a [Uint8List].
  @override
  Future<PublicKey> getPublicKey(String keyId) {
    final keyPair = _getKeyPair(keyId);
    return keyPair.publicKey;
  }

  /// Retrieves the key pair with the specified identifier.
  ///
  /// [keyId] - The identifier of the key pair to retrieve.
  ///
  /// Returns the [Secp256k1KeyPair].
  ///
  /// Throws an [ArgumentError] if the key is invalid.
  Secp256k1KeyPair _getKeyPair(String keyId) {
    if (_keyMap.containsKey(keyId)) {
      return _keyMap[keyId]!;
    } else {
      throw SsiException(
        message: 'Invalid Key ID: $keyId',
        code: SsiExceptionType.invalidKeyType.code,
      );
    }
  }

  /// Validates and parses a key identifier.
  ///
  /// [keyId] - The key identifier to validate and parse.
  ///
  /// Returns a tuple containing the account number and account key ID.
  ///
  /// Throws an [SsiException] if the key ID format is invalid.
  static (int, int) _validateKeyId(String keyId) {
    // NOTE: agree on approach for multikey support
    // option 1: keyId is composed as `{accountNumber}-{accountKeyId}`
    // option 2: separate the identifiers and require both
    // option 3: use the full derivation path as keyId
    var accountNumber = 0;
    var accountKeyId = 0;
    try {
      List<String> parts = keyId.split("-");
      accountNumber = int.parse(parts[0]);
      accountKeyId = int.parse(parts[1]);
    } catch (e) {
      throw SsiException(
        message:
            'For Bip32Ed25519Wallet the keyId is composed as {accountNumber}-{accountKeyId}, where both accountNumber and accountKeyId are positive integers',
        originalMessage: e.toString(),
        code: SsiExceptionType.other.code,
      );
    }
    return (accountNumber, accountKeyId);
  }

  /// Builds a derivation path from the base path and account information.
  ///
  /// [baseDerivationPath] - The base derivation path.
  /// [accountNumber] - The account number.
  /// [accountKeyId] - The account key ID.
  ///
  /// Returns the complete derivation path.
  static String _buildDerivationPath(
      String baseDerivationPath, int accountNumber, int accountKeyId) {
    List<String> parts = baseDerivationPath.split('/');
    parts[3] = "$accountNumber'";
    parts[5] = "$accountKeyId";
    return parts.join('/');
  }
}
