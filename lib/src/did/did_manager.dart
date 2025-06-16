import 'dart:convert';
import 'dart:typed_data';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/key_pair.dart';
import '../types.dart';
import '../util/base64_util.dart';
import '../wallet/persistent_wallet.dart';
import '../wallet/wallet.dart';
import 'did_document/did_document.dart';
import 'did_signer.dart';
import 'public_key_utils.dart';

/// A store for managing mappings between DID key identifiers and wallet key identifiers.
class DiDManagerStore {
  final Map<String, String> _keyMapping = {};

  /// Sets a mapping between a DID key identifier and a wallet key identifier.
  void setMapping(String didKeyId, String walletKeyId) {
    _keyMapping[didKeyId] = walletKeyId;
  }

  /// Gets the wallet key identifier for a given DID key identifier.
  String? getWalletKeyId(String didKeyId) {
    return _keyMapping[didKeyId];
  }

  /// Removes the mapping for a given DID key identifier.
  void removeMapping(String didKeyId) {
    _keyMapping.remove(didKeyId);
  }

  /// Clears all mappings.
  void clear() {
    _keyMapping.clear();
  }

  /// Gets all DID key identifiers.
  List<String> get didKeyIds => _keyMapping.keys.toList();
}

/// Base class for managing DID documents and their associated verification methods.
///
/// This abstract class provides shared functionality for creating and managing
/// DID documents with multiple verification methods, handling the mapping
/// between DID key identifiers and wallet key identifiers, and providing
/// signing and verification capabilities.
abstract class DidManager {
  /// The key mapping store for this manager.
  final DiDManagerStore keyMapping;

  /// The wallet instance for key operations.
  final Wallet wallet;

  DidDocument? _document;

  /// Creates a new DID manager instance.
  ///
  /// [keyMapping] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  /// [document] - An optional existing DID document to manage.
  DidManager({
    required this.keyMapping,
    required this.wallet,
    DidDocument? document,
  }) : _document = document;

  /// Gets the current DID document managed by this instance.
  DidDocument? get document => _document;

  /// Sets the managed DID document.
  ///
  /// [document] - The DID document to manage.
  void setDocument(DidDocument document) {
    _document = document;
  }

  /// Creates a new verification method with a new key.
  ///
  /// Generates a new key pair in the wallet and creates a verification method
  /// in the DID document. If no document exists, creates a new one.
  ///
  /// [keyType] - The type of key to generate.
  /// [keyId] - Optional key identifier. If not provided, generates one automatically.
  /// [signatureScheme] - Optional signature scheme to use.
  /// [useJwtThumbprint] - Whether to use JWT thumbprint for key ID generation.
  ///
  /// Returns the verification method identifier.
  Future<String> createVerificationMethod(
    KeyType keyType, {
    String? keyId,
    SignatureScheme? signatureScheme,
    bool useJwtThumbprint = false,
  });

  /// Adds a verification method using an existing key from the wallet.
  ///
  /// Creates a verification method in the DID document using an existing
  /// key from the wallet. If no document exists, creates a new one.
  ///
  /// [keyType] - The type of the existing key.
  /// [walletKeyId] - The identifier of the existing key in the wallet.
  /// [signatureScheme] - Optional signature scheme to use.
  ///
  /// Returns the verification method identifier.
  Future<String> addVerificationMethod(
    KeyType keyType,
    String walletKeyId, {
    SignatureScheme? signatureScheme,
  });

  /// Signs data using a verification method.
  ///
  /// [data] - The data to sign.
  /// [verificationMethodId] - The verification method identifier to use for signing.
  /// [signatureScheme] - Optional signature scheme to use.
  ///
  /// Returns the signature bytes.
  Future<Uint8List> sign(
    Uint8List data,
    String verificationMethodId, {
    SignatureScheme? signatureScheme,
  }) async {
    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    return wallet.sign(
      data,
      keyId: walletKeyId,
      signatureScheme: signatureScheme,
    );
  }

  /// Verifies a signature using a verification method.
  ///
  /// [data] - The original data that was signed.
  /// [signature] - The signature to verify.
  /// [verificationMethodId] - The verification method identifier to use for verification.
  /// [signatureScheme] - Optional signature scheme to use.
  ///
  /// Returns true if the signature is valid, false otherwise.
  Future<bool> verify(
    Uint8List data,
    Uint8List signature,
    String verificationMethodId, {
    SignatureScheme? signatureScheme,
  }) async {
    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    return wallet.verify(
      data,
      signature: signature,
      keyId: walletKeyId,
      signatureScheme: signatureScheme,
    );
  }

  /// Gets a DID signer for a verification method.
  ///
  /// Creates a DID signer that can be used for signing credentials and other
  /// DID-related operations.
  ///
  /// [verificationMethodId] - The verification method identifier to create a signer for.
  /// [signatureScheme] - Optional signature scheme to use.
  ///
  /// Returns a configured DID signer.
  Future<DidSigner> getSigner(
    String verificationMethodId, {
    SignatureScheme? signatureScheme,
  }) async {
    if (_document == null) {
      throw SsiException(
        message: 'No DID document available',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    final keyPair = await getKeyPair(walletKeyId);
    final effectiveSignatureScheme =
        signatureScheme ?? getDefaultSignatureScheme(keyPair);

    return DidSigner(
      didDocument: _document!,
      didKeyId: verificationMethodId,
      keyPair: keyPair,
      signatureScheme: effectiveSignatureScheme,
    );
  }

  /// Retrieves a key pair from the wallet.
  ///
  /// If the wallet is a PersistentWallet, retrieves an existing key pair.
  /// Otherwise, generates a new key pair with the given ID.
  Future<KeyPair> getKeyPair(String walletKeyId) async {
    if (wallet is PersistentWallet) {
      return (wallet as PersistentWallet).getKeyPair(walletKeyId);
    }

    return wallet.generateKey(keyId: walletKeyId);
  }

  /// Gets the default signature scheme for a key pair.
  ///
  /// Returns the first supported signature scheme if available,
  /// otherwise returns a default scheme based on the key type.
  SignatureScheme getDefaultSignatureScheme(KeyPair keyPair) {
    final supportedSchemes = keyPair.supportedSignatureSchemes;
    if (supportedSchemes.isNotEmpty) {
      return supportedSchemes.first;
    }

    switch (keyPair.publicKey.type) {
      case KeyType.secp256k1:
        return SignatureScheme.ecdsa_secp256k1_sha256;
      case KeyType.ed25519:
        return SignatureScheme.eddsa_sha512;
      case KeyType.p256:
        return SignatureScheme.ecdsa_p256_sha256;
      default:
        throw SsiException(
          message: 'Unsupported key type: ${keyPair.publicKey.type}',
          code: SsiExceptionType.unsupportedSignatureScheme.code,
        );
    }
  }

  /// Generates a key identifier.
  String generateKeyId() {
    return 'key-${DateTime.now().millisecondsSinceEpoch}';
  }

  /// Generates a JWT thumbprint-based key identifier.
  ///
  /// Creates a key identifier based on the JWT thumbprint specification (RFC 7638).
  /// This provides a more standardized and deterministic way to generate key IDs
  /// compared to timestamp-based generation.
  ///
  /// [keyType] - The key type to generate a thumbprint for.
  ///
  /// Returns a JWT thumbprint-based key identifier.
  Future<String> generateJwtThumbprintKeyId(KeyType keyType) async {
    final tempKeyPair = await wallet.generateKey(keyType: keyType);
    final multikey = toMultikey(tempKeyPair.publicKey.bytes, keyType);
    final publicKeyJwk = multiKeyToJwk(multikey);

    final sortedKeys = Map.fromEntries(
        publicKeyJwk.entries.toList()..sort((a, b) => a.key.compareTo(b.key)));

    final canonicalJson = jsonEncode(sortedKeys);
    final thumbprintBytes = utf8.encode(canonicalJson);

    return 'key-${base64UrlNoPadEncode(thumbprintBytes)}';
  }
}
