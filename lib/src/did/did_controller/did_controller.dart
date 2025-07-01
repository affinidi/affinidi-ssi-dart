import 'dart:typed_data';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/key_pair.dart';
import '../../key_pair/public_key.dart';
import '../../types.dart';
import '../../wallet/persistent_wallet.dart';
import '../../wallet/wallet.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint.dart';
import '../did_key_pair.dart';
import '../did_signer.dart';
import '../stores/did_store_interface.dart';

/// Base class for managing DID documents and their associated verification methods.
///
/// This abstract class provides shared functionality for creating and managing
/// DID documents with multiple verification methods, handling the mapping
/// between DID key identifiers and wallet key identifiers, and providing
/// signing and verification capabilities.
abstract class DidController {
  /// The key mapping store for this controller.
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

  /// Creates a new DID controller instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidController({
    required this.store,
    required this.wallet,
  });

  /// Gets the current DID document by creating or updating it from the current state.
  ///
  /// This method ensures that the returned document reflects the latest state
  /// of verification methods and their purposes. Developers should call this
  /// method whenever they need access to the current DID document.
  ///
  /// Returns the current DID document.
  Future<DidDocument> getDidDocument();

  /// Adds a verification method using an existing key from the wallet.
  Future<String> addVerificationMethod(PublicKey publicKey) async {
    final verificationMethodId = await buildVerificationMethodId(publicKey);
    await store.setMapping(verificationMethodId, publicKey.id);
    _cacheVerificationMethodIdToWalletKeyId[verificationMethodId] =
        publicKey.id;
    return verificationMethodId;
  }

  // TODO: Function to remove verification method
  // Careful as all verification id's may need to be recalculated. In did:peer they are indexed

  /// Builds the verification method ID for a given public key.
  /// Subclasses implement this to handle method-specific ID construction.
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

  /// Clears all controller state and underlying storage.
  Future<void> clearAll() async {
    _cacheVerificationMethodIdToWalletKeyId.clear();
    _cacheAuthentication.clear();
    _cacheKeyAgreement.clear();
    _cacheCapabilityInvocation.clear();
    _cacheCapabilityDelegation.clear();
    _cacheAssertionMethod.clear();
    _cacheService.clear();
    await store.clearAll();
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
      didDocument: didDocument,
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
}
