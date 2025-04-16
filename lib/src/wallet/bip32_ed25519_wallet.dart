import 'dart:typed_data';

import 'package:ed25519_hd_key/ed25519_hd_key.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/ed25519_key_pair.dart';
import '../key_pair/public_key.dart';
import '../wallet/key_store/key_store_interface.dart';
import '../types.dart';
import 'wallet.dart';

/// A wallet implementation that supports BIP32 key derivation with Ed25519 keys.
///
/// This wallet can create and manage multiple key pairs derived from a single seed.
/// It supports signing and verifying messages using Ed25519 signature scheme.
class Bip32Ed25519Wallet implements Wallet {
  /// The base derivation path.
  static const baseDerivationPath = "m/44'/60'/0'/0'/0'";

  /// The identifier for the root key pair.
  static const rootKeyId = "0-0";

  /// The map of key identifiers to key pairs.
  final Map<String, Ed25519KeyPair> _keyMap;

  /// Creates a new [Bip32Ed25519Wallet] instance with the given key map.
  Bip32Ed25519Wallet._(this._keyMap);

  /// Creates a new [Bip32Ed25519Wallet] instance from a seed.
  ///
  /// [seed] - The seed to use for key derivation.
  ///
  /// Returns a [Future] that completes with the newly created wallet.
  static Future<Bip32Ed25519Wallet> fromSeed(Uint8List seed) async {
    KeyData master = await ED25519_HD_KEY.getMasterKeyFromSeed(seed);
    final rootKeyPair = Ed25519KeyPair.fromSeed(Uint8List.fromList(master.key));
    Map<String, Ed25519KeyPair> keyMap = {rootKeyId: rootKeyPair};
    return Bip32Ed25519Wallet._(keyMap);
  }

  /// Creates a new [Bip32Ed25519Wallet] instance from a KeyStore by retrieving the seed.
  ///
  /// [keyStore] - The KeyStore to use to fetch the seed.
  ///
  /// Returns a [Future] that completes with the new [Bip32Ed25519Wallet] instance.
  /// Throws [ArgumentError] if the seed is not found in the KeyStore.
  static Future<Bip32Ed25519Wallet> createFromKeyStore(
    KeyStore keyStore,
  ) async {
    final storedSeed = await keyStore.getSeed();
    if (storedSeed == null) {
      throw ArgumentError(
          'Seed not found in KeyStore. Cannot create Bip32Ed25519Wallet.');
    }
    // Bip32Ed25519Wallet.fromSeed is async, so we await it
    return await Bip32Ed25519Wallet.fromSeed(storedSeed);
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
  /// [keyType] - The type of key to create
  ///
  /// Returns a [Future] that completes with the newly created [Ed25519KeyPair].
  ///
  /// Throws an [SsiException] if:
  /// - Unsupported key type
  /// - The root key pair is missing
  @override
  Future<PublicKey> createKeyPair(String keyId, {KeyType? keyType}) async {
    if (keyType != null && keyType != KeyType.ed25519) {
      throw SsiException(
        message:
            'Unsupported key type. Only ed25519 key type is supported for Bip32Ed25519Wallet.',
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
    final seedBytes = _keyMap[rootKeyId]!.getSeed();

    KeyData derived =
        await ED25519_HD_KEY.derivePath(derivationPath, seedBytes.toList());

    final keyPair = Ed25519KeyPair.fromSeed(Uint8List.fromList(derived.key));
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
  /// Returns the [Ed25519KeyPair].
  ///
  /// Throws an [SsiException] if the key is invalid.
  Ed25519KeyPair _getKeyPair(String keyId) {
    if (_keyMap.containsKey(keyId)) {
      return _keyMap[keyId]!;
    } else {
      throw SsiException(
        message: 'Invalid Key ID: $keyId',
        code: SsiExceptionType.keyPairMissingPrivateKey.code,
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
            'keyId must be in format {accountNumber}-{accountKeyId}, both positive integers.',
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
    parts[5] = "$accountKeyId'";
    return parts.join('/');
  }
}
