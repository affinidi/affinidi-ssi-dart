import 'dart:convert';
import 'dart:typed_data';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import '../util/base64_util.dart';
import '../wallet/persistent_wallet.dart';
import '../wallet/wallet.dart';
import 'did_document/did_document.dart';
import 'did_document/service_endpoint_value.dart';
import 'did_document/verification_method.dart';
import 'did_key.dart';
import 'did_peer.dart';
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

/// Manages DID documents and their associated verification methods.
///
/// This class provides a high-level interface for creating and managing
/// DID documents with multiple verification methods, handling the mapping
/// between DID key identifiers and wallet key identifiers, and providing
/// signing and verification capabilities.
///
/// The manager supports different DID methods and provides centralized
/// document creation and management functionality.
class DiDManager {
  /// The key mapping store for this manager.
  final DiDManagerStore keyMapping;
  final Wallet _wallet;
  DidDocument? _document;

  /// Creates a new DID manager instance.
  ///
  /// [keyMapping] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  /// [document] - An optional existing DID document to manage.
  ///
  /// TODO: Enhance DID and document creation management:
  /// - Support multiple DID methods (did:key, did:peer, did:web)
  /// - Provide configurable document creation strategies
  /// - Add validation for document consistency
  /// - Support document updates and key rotation
  DiDManager({
    required this.keyMapping,
    required Wallet wallet,
    DidDocument? document,
  })  : _wallet = wallet,
        _document = document;

  /// Gets the current DID document managed by this instance.
  DidDocument? get document => _document;

  /// Creates a DID document using the specified method.
  ///
  /// [publicKeys] - The public keys to include in the document.
  /// [method] - The DID method to use ('key', 'peer', 'web').
  /// [serviceEndpoint] - Optional service endpoint for did:peer.
  ///
  /// Returns the created DID document.
  DidDocument createDidDocument(
    List<PublicKey> publicKeys, {
    String method = 'key',
    String? serviceEndpoint,
  }) {
    switch (method.toLowerCase()) {
      case 'key':
        if (publicKeys.length != 1) {
          throw SsiException(
            message: 'did:key method requires exactly one public key',
            code: SsiExceptionType.invalidDidDocument.code,
          );
        }
        return DidKey.generateDocument(publicKeys.first);

      case 'peer':
        final serviceValue =
            serviceEndpoint != null ? StringEndpoint(serviceEndpoint) : null;
        return DidPeer.generateDocument(
          publicKeys,
          serviceEndpoint: serviceValue,
        );

      default:
        throw SsiException(
          message: 'Unsupported DID method: $method',
          code: SsiExceptionType.invalidDidDocument.code,
        );
    }
  }

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
  }) async {
    final walletKeyId = keyId ??
        (useJwtThumbprint
            ? await _generateJwtThumbprintKeyId(keyType)
            : _generateKeyId());
    final keyPair = await _wallet.generateKey(
      keyId: walletKeyId,
      keyType: keyType,
    );

    final didDocument = DidKey.generateDocument(keyPair.publicKey);
    final verificationMethodId = didDocument.verificationMethod.first.id;

    keyMapping.setMapping(verificationMethodId, walletKeyId);

    if (_document == null) {
      _document = didDocument;
    } else {
      _addVerificationMethodToDocument(didDocument.verificationMethod.first);
    }

    return verificationMethodId;
  }

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
  }) async {
    final publicKey = await _wallet.getPublicKey(walletKeyId);
    final didDocument = DidKey.generateDocument(publicKey);
    final verificationMethodId = didDocument.verificationMethod.first.id;

    keyMapping.setMapping(verificationMethodId, walletKeyId);

    if (_document == null) {
      _document = didDocument;
    } else {
      _addVerificationMethodToDocument(didDocument.verificationMethod.first);
    }

    return verificationMethodId;
  }

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

    return _wallet.sign(
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

    return _wallet.verify(
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

    final keyPair = await _getKeyPair(walletKeyId);
    final effectiveSignatureScheme =
        signatureScheme ?? _getDefaultSignatureScheme(keyPair);

    return DidSigner(
      didDocument: _document!,
      didKeyId: verificationMethodId,
      keyPair: keyPair,
      signatureScheme: effectiveSignatureScheme,
    );
  }

  Future<KeyPair> _getKeyPair(String walletKeyId) async {
    if (_wallet is PersistentWallet) {
      return _wallet.getKeyPair(walletKeyId);
    }

    return _wallet.generateKey(keyId: walletKeyId);
  }

  SignatureScheme _getDefaultSignatureScheme(KeyPair keyPair) {
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

  void _addVerificationMethodToDocument(
      EmbeddedVerificationMethod verificationMethod) {
    if (_document == null) return;

    final updatedVerificationMethods =
        List<EmbeddedVerificationMethod>.from(_document!.verificationMethod)
          ..add(verificationMethod);

    final updatedAuthentication =
        List<VerificationMethod>.from(_document!.authentication)
          ..add(VerificationMethodRef(
              reference: verificationMethod.id, method: verificationMethod));

    final updatedAssertionMethod =
        List<VerificationMethod>.from(_document!.assertionMethod)
          ..add(VerificationMethodRef(
              reference: verificationMethod.id, method: verificationMethod));

    final updatedCapabilityInvocation =
        List<VerificationMethod>.from(_document!.capabilityInvocation)
          ..add(VerificationMethodRef(
              reference: verificationMethod.id, method: verificationMethod));

    final updatedCapabilityDelegation =
        List<VerificationMethod>.from(_document!.capabilityDelegation)
          ..add(VerificationMethodRef(
              reference: verificationMethod.id, method: verificationMethod));

    _document = DidDocument.create(
      context: _document!.context,
      id: _document!.id,
      alsoKnownAs: _document!.alsoKnownAs,
      controller: _document!.controller,
      verificationMethod: updatedVerificationMethods,
      authentication: updatedAuthentication,
      assertionMethod: updatedAssertionMethod,
      keyAgreement: _document!.keyAgreement,
      capabilityInvocation: updatedCapabilityInvocation,
      capabilityDelegation: updatedCapabilityDelegation,
      service: _document!.service,
    );
  }

  String _generateKeyId() {
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
  Future<String> _generateJwtThumbprintKeyId(KeyType keyType) async {
    final tempKeyPair = await _wallet.generateKey(keyType: keyType);
    final multikey = toMultikey(tempKeyPair.publicKey.bytes, keyType);
    final publicKeyJwk = multiKeyToJwk(multikey);

    final sortedKeys = Map.fromEntries(
        publicKeyJwk.entries.toList()..sort((a, b) => a.key.compareTo(b.key)));

    final canonicalJson = jsonEncode(sortedKeys);
    final thumbprintBytes = utf8.encode(canonicalJson);

    return 'key-${base64UrlNoPadEncode(thumbprintBytes)}';
  }
}
