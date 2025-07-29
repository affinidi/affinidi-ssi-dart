import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/key_pair.dart';
import '../../key_pair/public_key.dart';
import '../../types.dart';
import '../../utility.dart';
import '../../wallet/persistent_wallet.dart';
import '../../wallet/wallet.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint.dart';
import '../did_key_pair.dart';
import '../did_signer.dart';
import '../stores/did_store_interface.dart';
import 'add_verification_method_result.dart';
import 'verification_relationship.dart';

/// Base class for managing DID documents and their associated verification methods.
///
/// This abstract class provides shared functionality for creating and managing
/// DID documents with multiple verification methods, handling the mapping
/// between DID key identifiers and wallet key identifiers, and providing
/// signing and verification capabilities.
///
/// ## Usage
///
/// To create a properly initialized manager, use the [create] static method:
///
/// ```dart
/// final manager = await DidManager.create(
///   () => DidPeerManager(store: store, wallet: wallet),
/// );
/// ```
///
/// Alternatively, if using the constructor directly, you must call [init] after construction:
///
/// ```dart
/// final manager = DidPeerManager(store: store, wallet: wallet);
/// await manager.init();
/// ```
abstract class DidManager {
  /// The key mapping store for this manager.
  final DidStore store;

  /// Cache for verification method ID to wallet key ID mappings
  final Map<String, String> _cacheVerificationMethodIdToWalletKeyId = {};

  /// Cache for verification methods
  final List<String> _cacheAuthentication = [];
  final List<String> _cacheKeyAgreement = [];
  final List<String> _cacheCapabilityInvocation = [];
  final List<String> _cacheCapabilityDelegation = [];
  final List<String> _cacheAssertionMethod = [];
  final List<ServiceEndpoint> _cacheService = [];

  /// Verification method references for authentication purposes
  Iterable<String> get authentication => _cacheAuthentication;

  /// Verification method references for key agreement purposes
  Iterable<String> get keyAgreement => _cacheKeyAgreement;

  /// Verification method references for capability invocation purposes
  Iterable<String> get capabilityInvocation => _cacheCapabilityInvocation;

  /// Verification method references for capability delegation purposes
  Iterable<String> get capabilityDelegation => _cacheCapabilityDelegation;

  /// Verification method references for assertion purposes
  Iterable<String> get assertionMethod => _cacheAssertionMethod;

  /// Service endpoints
  Iterable<ServiceEndpoint> get service => _cacheService;

  /// Adds a service endpoint to the DID document.
  ///
  /// Throws an [SsiException] if a service endpoint with the same ID already exists.
  Future<void> addServiceEndpoint(ServiceEndpoint endpoint) async {
    if (_cacheService.any((se) => se.id == endpoint.id)) {
      throw SsiException(
        message: 'Service endpoint with id ${endpoint.id} already exists',
        code: SsiExceptionType.other.code,
      );
    }
    _cacheService.add(endpoint);
    await store.addServiceEndpoint(endpoint);
  }

  /// Removes a service endpoint from the DID document by its ID.
  Future<void> removeServiceEndpoint(String id) async {
    _cacheService.removeWhere((se) => se.id == id);
    await store.removeServiceEndpoint(id);
  }

  /// The wallet instance for key operations.
  final Wallet wallet;

  /// Creates a new DID manager instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidManager({
    required this.store,
    required this.wallet,
  });

  /// Creates and initializes a new DID manager instance.
  ///
  /// This factory method ensures that the manager is properly initialized
  /// by calling [init] after construction.
  ///
  /// [factory] - A function that creates the manager instance.
  ///
  /// Returns a fully initialized manager instance.
  static Future<T> create<T extends DidManager>(
    T Function() factory,
  ) async {
    final manager = factory();
    await manager.init();
    return manager;
  }

  /// Initializes the manager by loading data from the store.
  Future<void> init() async {
    _cacheAuthentication.addAll(await store.authentication);
    _cacheKeyAgreement.addAll(await store.keyAgreement);
    _cacheCapabilityInvocation.addAll(await store.capabilityInvocation);
    _cacheCapabilityDelegation.addAll(await store.capabilityDelegation);
    _cacheAssertionMethod.addAll(await store.assertionMethod);
    _cacheService.addAll(await store.serviceEndpoints);
  }

  /// Gets the current DID document by creating or updating it from the current state.
  ///
  /// This method ensures that the returned document reflects the latest state
  /// of verification methods and their purposes. Developers should call this
  /// method whenever they need access to the current DID document.
  ///
  /// Returns the current DID document.
  Future<DidDocument> getDidDocument();

  Set<VerificationRelationship> _getDefaultRelationships(KeyType keyType) {
    switch (keyType) {
      case KeyType.x25519:
        return {VerificationRelationship.keyAgreement};
      case KeyType.secp256k1:
        return {
          VerificationRelationship.authentication,
          VerificationRelationship.assertionMethod,
          VerificationRelationship.capabilityInvocation,
          VerificationRelationship.capabilityDelegation,
        };
      case KeyType.ed25519:
      case KeyType.p256:
      case KeyType.p384:
      case KeyType.p521:
      case KeyType.rsa:
        return {
          VerificationRelationship.keyAgreement,
          VerificationRelationship.authentication,
          VerificationRelationship.assertionMethod,
          VerificationRelationship.capabilityInvocation,
          VerificationRelationship.capabilityDelegation,
        };
    }
  }

  /// Adds a key from the wallet to the DID, creating verification methods
  /// and assigning them to verification relationships.
  ///
  /// [walletKeyId] - The ID of the key in the wallet.
  /// [relationships] - The relationships this key should have.
  ///
  /// - If `null` (default), a sensible set of relationships is chosen based
  ///   on the key type:
  ///   - **x25519**: `keyAgreement`
  ///   - **secp256k1**: `authentication`, `assertionMethod`, `capabilityInvocation`, `capabilityDelegation`
  ///   - **ed25519, p256, p384, p521, rsa**: `keyAgreement`, `authentication`, `assertionMethod`, `capabilityInvocation`, `capabilityDelegation`
  /// - If an empty set (`{}`) is provided, the key is added to the DID
  ///   document's `verificationMethod` list but not assigned to any
  ///   relationship.
  /// - If a custom set is provided, the key will be assigned to the specified
  ///   relationships. An [ArgumentError] will be thrown if the key type is
  ///   unsuitable for a requested relationship (e.g., using an X25519 key
  ///   for `authentication`).
  ///
  ///   Note: When an `ed25519` key is used for `keyAgreement`, it is
  ///   automatically converted to an `x25519` key, resulting in a separate
  ///   verification method.
  ///
  /// Returns an [AddVerificationMethodResult] containing the primary
  /// verification method ID and a map of assigned relationships.
  Future<AddVerificationMethodResult> addVerificationMethod(
    String walletKeyId, {
    Set<VerificationRelationship>? relationships,
  }) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    final effectiveRelationships =
        relationships ?? _getDefaultRelationships(publicKey.type);

    return internalAddVerificationMethod(
      walletKeyId,
      publicKey: publicKey,
      relationships: effectiveRelationships,
    );
  }

  /// Adds a key from the wallet to the DID, creating verification methods
  /// and assigning them to verification relationships.
  ///
  /// This is the internal method that subclasses should override to implement
  /// method-specific logic. The public [addVerificationMethod] handles
  /// default relationship logic and then calls this method.
  ///
  /// [walletKeyId] - The ID of the key in the wallet.
  /// [publicKey] - The public key object.
  /// [relationships] - The relationships this key should have. This set is
  /// guaranteed to be non-null.
  ///
  /// Returns an [AddVerificationMethodResult].
  @protected
  Future<AddVerificationMethodResult> internalAddVerificationMethod(
    String walletKeyId, {
    required PublicKey publicKey,
    required Set<VerificationRelationship> relationships,
  }) async {
    final resultMap = <VerificationRelationship, String>{};
    String? verificationMethodId;

    // If we only need key agreement for an ed25519 key, we don't create a
    // primary VM for the ed25519 key itself, only for the derived x25519 key.
    final onlyKeyAgreementForEd25519 = relationships.length == 1 &&
        relationships.first == VerificationRelationship.keyAgreement &&
        publicKey.type == KeyType.ed25519;

    if (!onlyKeyAgreementForEd25519) {
      verificationMethodId =
          await addVerificationMethodFromPublicKey(publicKey);
    }

    for (final relationship in relationships) {
      switch (relationship) {
        case VerificationRelationship.keyAgreement:
          if (publicKey.type == KeyType.ed25519) {
            final x25519PublicKeyBytes =
                ed25519PublicToX25519Public(publicKey.bytes);
            final x25519PublicKey =
                PublicKey(walletKeyId, x25519PublicKeyBytes, KeyType.x25519);
            final keyAgreementId = await addVerificationMethodFromPublicKey(
              x25519PublicKey,
            );
            await _addRelationship(relationship, keyAgreementId);
            resultMap[relationship] = keyAgreementId;
            // If no primary VM was created, use this one as the primary ID.
            verificationMethodId ??= keyAgreementId;
          } else {
            await _addRelationship(relationship, verificationMethodId!);
            resultMap[relationship] = verificationMethodId;
          }
          break;

        case VerificationRelationship.authentication:
        case VerificationRelationship.assertionMethod:
        case VerificationRelationship.capabilityInvocation:
        case VerificationRelationship.capabilityDelegation:
          if (publicKey.type == KeyType.x25519) {
            throw ArgumentError(
              'The key type ${publicKey.type} cannot be used for the '
              '"$relationship" relationship.',
            );
          }

          await _addRelationship(relationship, verificationMethodId!);
          resultMap[relationship] = verificationMethodId;
          break;
      }
    }

    // If relationships was an empty set, a VM should have been created.
    if (relationships.isEmpty) {
      verificationMethodId ??=
          await addVerificationMethodFromPublicKey(publicKey);
    }

    return AddVerificationMethodResult(
      verificationMethodId: verificationMethodId!,
      relationships: resultMap,
    );
  }

  /// Adds a verification method to the store and cache.
  @protected
  Future<String> addVerificationMethodFromPublicKey(
    PublicKey publicKey, {
    String? verificationMethodId,
  }) async {
    final vmId =
        verificationMethodId ?? await buildVerificationMethodId(publicKey);
    await store.setMapping(vmId, publicKey.id);
    _cacheVerificationMethodIdToWalletKeyId[vmId] = publicKey.id;
    return vmId;
  }

  Future<void> _addRelationship(
    VerificationRelationship relationship,
    String verificationMethodId,
  ) async {
    final addFunction = switch (relationship) {
      VerificationRelationship.authentication => addAuthentication,
      VerificationRelationship.assertionMethod => addAssertionMethod,
      VerificationRelationship.capabilityInvocation => addCapabilityInvocation,
      VerificationRelationship.capabilityDelegation => addCapabilityDelegation,
      VerificationRelationship.keyAgreement => addKeyAgreement,
    };
    await addFunction(verificationMethodId);
  }

  // TODO: Add function to remove verification method
  // Note: All verification IDs may need recalculation in did:peer (they are indexed)

  /// Builds the verification method ID for a given public key.
  /// Subclasses implement this to handle method-specific ID construction.
  ///
  /// [publicKey] - The public key to create a verification method ID for.
  Future<String> buildVerificationMethodId(PublicKey publicKey);

  /// Gets the stored wallet key ID that corresponds to the provided verification method ID
  Future<String?> getWalletKeyId(String verificationMethodId) async {
    if (_cacheVerificationMethodIdToWalletKeyId
        .containsKey(verificationMethodId)) {
      return _cacheVerificationMethodIdToWalletKeyId[verificationMethodId];
    }

    final walletKeyId = await store.getWalletKeyId(verificationMethodId);
    if (walletKeyId != null) {
      _cacheVerificationMethodIdToWalletKeyId[verificationMethodId] =
          walletKeyId;
    }
    return walletKeyId;
  }

  /// Adds an existing verification method reference to authentication.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  /// - verification method is not found in mapping
  Future<void> addAuthentication(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }

    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_cacheAuthentication.contains(verificationMethodId)) {
      _cacheAuthentication.add(verificationMethodId);
      await store.addAuthentication(verificationMethodId);
    }
  }

  /// Adds an existing verification method reference to key agreement.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  /// - verification method is not found in mapping
  Future<void> addKeyAgreement(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }

    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_cacheKeyAgreement.contains(verificationMethodId)) {
      _cacheKeyAgreement.add(verificationMethodId);
      await store.addKeyAgreement(verificationMethodId);
    }
  }

  /// Adds an existing verification method reference to capability invocation.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  /// - verification method is not found in mapping
  Future<void> addCapabilityInvocation(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }

    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_cacheCapabilityInvocation.contains(verificationMethodId)) {
      _cacheCapabilityInvocation.add(verificationMethodId);
      await store.addCapabilityInvocation(verificationMethodId);
    }
  }

  /// Adds an existing verification method reference to capability delegation.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  /// - verification method is not found in mapping
  Future<void> addCapabilityDelegation(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }

    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_cacheCapabilityDelegation.contains(verificationMethodId)) {
      _cacheCapabilityDelegation.add(verificationMethodId);
      await store.addCapabilityDelegation(verificationMethodId);
    }
  }

  /// Adds an existing verification method reference to assertion method.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  /// - verification method is not found in mapping
  Future<void> addAssertionMethod(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }

    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_cacheAssertionMethod.contains(verificationMethodId)) {
      _cacheAssertionMethod.add(verificationMethodId);
      await store.addAssertionMethod(verificationMethodId);
    }
  }

  /// Removes a verification method reference from authentication.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  Future<void> removeAuthentication(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }
    if (_cacheAuthentication.remove(verificationMethodId)) {
      await store.removeAuthentication(verificationMethodId);
    }
  }

  /// Removes a verification method reference from key agreement.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  Future<void> removeKeyAgreement(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }
    if (_cacheKeyAgreement.remove(verificationMethodId)) {
      await store.removeKeyAgreement(verificationMethodId);
    }
  }

  /// Removes a verification method reference from capability invocation.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  Future<void> removeCapabilityInvocation(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }
    if (_cacheCapabilityInvocation.remove(verificationMethodId)) {
      await store.removeCapabilityInvocation(verificationMethodId);
    }
  }

  /// Removes a verification method reference from capability delegation.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  Future<void> removeCapabilityDelegation(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }
    if (_cacheCapabilityDelegation.remove(verificationMethodId)) {
      await store.removeCapabilityDelegation(verificationMethodId);
    }
  }

  /// Removes a verification method reference from assertion method.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  Future<void> removeAssertionMethod(String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }
    if (_cacheAssertionMethod.remove(verificationMethodId)) {
      await store.removeAssertionMethod(verificationMethodId);
    }
  }

  /// Removes a verification method reference from all verification relationships.
  ///
  /// Throws [SsiException] if:
  /// - verificationMethodId is empty
  Future<void> removeAllVerificationMethodReferences(
      String verificationMethodId) async {
    if (verificationMethodId.isEmpty) {
      throw SsiException(
        message: 'Verification method ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }
    if (_cacheAuthentication.remove(verificationMethodId)) {
      await store.removeAuthentication(verificationMethodId);
    }
    if (_cacheKeyAgreement.remove(verificationMethodId)) {
      await store.removeKeyAgreement(verificationMethodId);
    }
    if (_cacheCapabilityInvocation.remove(verificationMethodId)) {
      await store.removeCapabilityInvocation(verificationMethodId);
    }
    if (_cacheCapabilityDelegation.remove(verificationMethodId)) {
      await store.removeCapabilityDelegation(verificationMethodId);
    }
    if (_cacheAssertionMethod.remove(verificationMethodId)) {
      await store.removeAssertionMethod(verificationMethodId);
    }
  }

  /// Protected method to clear all verification method references.
  /// This is intended for use by subclasses that need to manage their own verification methods.
  Future<void> clearVerificationMethodReferences() async {
    _cacheAuthentication.clear();
    _cacheKeyAgreement.clear();
    _cacheCapabilityInvocation.clear();
    _cacheCapabilityDelegation.clear();
    _cacheAssertionMethod.clear();
    await store.clearVerificationMethodReferences();
  }

  /// Protected method to clear all service endpoints.
  Future<void> clearServiceEndpoints() async {
    _cacheService.clear();
    await store.clearServiceEndpoints();
  }

  /// Clears all manager state and underlying storage.
  Future<void> clearAll() async {
    await store.clearAll();
    _cacheVerificationMethodIdToWalletKeyId.clear();
    _cacheAuthentication.clear();
    _cacheKeyAgreement.clear();
    _cacheCapabilityInvocation.clear();
    _cacheCapabilityDelegation.clear();
    _cacheAssertionMethod.clear();
    _cacheService.clear();
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
    final walletKeyId = await getWalletKeyId(verificationMethodId);
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
    final walletKeyId = await getWalletKeyId(verificationMethodId);
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
    final didDocument = await getDidDocument();

    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    final keyPair = await getKeyPair(walletKeyId);
    final effectiveSignatureScheme =
        signatureScheme ?? keyPair.defaultSignatureScheme;

    return DidSigner(
      did: didDocument.id,
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

  /// Retrieves a DID key pair for a verification method.
  ///
  /// Creates a DidKeyPair that combines the cryptographic key pair with
  /// its DID context, including the verification method ID and optional
  /// DID document.
  ///
  /// [verificationMethodId] - The DID verification method identifier to retrieve.
  ///
  /// Returns a [DidKeyPair] containing the key pair and DID context.
  ///
  /// Throws [SsiException] if the verification method is not found in the mapping.
  Future<DidKeyPair> getKey(String verificationMethodId) async {
    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    final keyPair = await getKeyPair(walletKeyId);

    final didDocument = await getDidDocument();

    return DidKeyPair(
      keyPair: keyPair,
      verificationMethodId: verificationMethodId,
      didDocument: didDocument,
    );
  }

  /// Retrieves the [KeyPair] associated with the given [didKeyId] from this [DidManager].
  ///
  /// Throws if the key is not found or cannot be retrieved.
  Future<KeyPair> getKeyPairByDidKeyId(String didKeyId) async {
    final keyId = await getWalletKeyIdUniversally(didKeyId);

    if (keyId == null) {
      throw Exception('Key ID not found for DID key ID: $didKeyId');
    }

    return await getKeyPair(keyId);
  }

  /// Retrieves the wallet key associated with the given [didKeyId] universally.
  ///
  /// Tries to find the key by the fully qualified DID key ID first.
  /// If not found, tries to find by the fragment after the hash sign.
  ///
  /// Returns a [String] containing the wallet key if found, or `null` if no key is associated
  /// with the provided [didKeyId].
  Future<String?> getWalletKeyIdUniversally(String didKeyId) async {
    var keyId = await getWalletKeyId(didKeyId);
    keyId ??= await getWalletKeyId(getKeyIdFromId(didKeyId));

    return keyId;
  }

  /// Extracts the key identifier from a given DID (Decentralized Identifier) string.
  ///
  /// The [id] parameter is expected to be a DID URL or identifier containing a key reference.
  ///
  /// Returns the key identifier as a [String].
  String getKeyIdFromId(String id) {
    return '#${id.split('#').last}';
  }
}
