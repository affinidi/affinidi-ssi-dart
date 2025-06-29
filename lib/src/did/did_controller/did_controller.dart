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
  final Map<String, String> _verificationMethodIdToWalletKeyId = {};

  /// Cache for verification methods
  final List<String> _authentication = [];
  final List<String> _keyAgreement = [];
  final List<String> _capabilityInvocation = [];
  final List<String> _capabilityDelegation = [];
  final List<String> _assertionMethod = [];

  /// Verification method references for authentication purposes
  Iterable<String> get authentication => _authentication;

  /// Verification method references for key agreement purposes
  Iterable<String> get keyAgreement => _keyAgreement;

  /// Verification method references for capability invocation purposes
  Iterable<String> get capabilityInvocation => _capabilityInvocation;

  /// Verification method references for capability delegation purposes
  Iterable<String> get capabilityDelegation => _capabilityDelegation;

  /// Verification method references for assertion purposes
  Iterable<String> get assertionMethod => _assertionMethod;

  /// TODO: Service endpoints

  void addServiceEndpoint(ServiceEndpoint endpoint) {
    // TODO
    // Check that the id doesnt exist already and add the service endpoint
  }

  void removeServiceEndpoint() {
    // What can be passed as a parameter to identify the endpoint to remove?
    // TODO
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
  Future<DidDocument> getDidDocument() async {
    // Get the base document from the child implementation
    final baseDocument = await createOrUpdateDocument();

    // Merge the base class verification method references with the document
    // The base class stores verification method IDs as strings,
    // so we need to use them as references in the document
    return DidDocument.create(
      context: baseDocument.context,
      id: baseDocument.id,
      controller: baseDocument.controller,
      alsoKnownAs: baseDocument.alsoKnownAs,
      verificationMethod: baseDocument.verificationMethod,
      // Merge base class references with document's existing references
      authentication: [
        ...baseDocument.authentication,
        ..._authentication,
      ],
      assertionMethod: [
        ...baseDocument.assertionMethod,
        ..._assertionMethod,
      ],
      keyAgreement: [
        ...baseDocument.keyAgreement,
        ..._keyAgreement,
      ],
      capabilityInvocation: [
        ...baseDocument.capabilityInvocation,
        ..._capabilityInvocation,
      ],
      capabilityDelegation: [
        ...baseDocument.capabilityDelegation,
        ..._capabilityDelegation,
      ],
      service: baseDocument.service,
    );
  }

  /// Creates or updates the DID document based on current state.
  /// Subclasses implement this to handle method-specific document creation.
  Future<DidDocument> createOrUpdateDocument();

  /// Adds a verification method using an existing key from the wallet.
  Future<String> addVerificationMethod(String walletKeyId) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    final verificationMethodId = await buildVerificationMethodId(publicKey);
    await store.setMapping(verificationMethodId, walletKeyId);
    _verificationMethodIdToWalletKeyId[verificationMethodId] = walletKeyId;
    return verificationMethodId;
  }

  // TODO: remove verification method
  // Needs to be careful as all verification id's may need to be recalculated. In did:peer they are indexed

  /// Gets the verification method ID for a given public key.
  /// Subclasses implement this to handle method-specific ID construction.
  Future<String> buildVerificationMethodId(PublicKey publicKey);

  Future<String?> _getWalletKeyId(String verificationMethodId) async {
    if (_verificationMethodIdToWalletKeyId.containsKey(verificationMethodId)) {
      return _verificationMethodIdToWalletKeyId[verificationMethodId];
    }

    final walletKeyId = await store.getWalletKeyId(verificationMethodId);
    if (walletKeyId != null) {
      _verificationMethodIdToWalletKeyId[verificationMethodId] = walletKeyId;
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

    final walletKeyId = await _getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_authentication.contains(verificationMethodId)) {
      _authentication.add(verificationMethodId);
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

    final walletKeyId = await _getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_keyAgreement.contains(verificationMethodId)) {
      _keyAgreement.add(verificationMethodId);
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

    final walletKeyId = await _getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_capabilityInvocation.contains(verificationMethodId)) {
      _capabilityInvocation.add(verificationMethodId);
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

    final walletKeyId = await _getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_capabilityDelegation.contains(verificationMethodId)) {
      _capabilityDelegation.add(verificationMethodId);
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

    final walletKeyId = await _getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    if (!_assertionMethod.contains(verificationMethodId)) {
      _assertionMethod.add(verificationMethodId);
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
    if (_authentication.remove(verificationMethodId)) {
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
    if (_keyAgreement.remove(verificationMethodId)) {
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
    if (_capabilityInvocation.remove(verificationMethodId)) {
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
    if (_capabilityDelegation.remove(verificationMethodId)) {
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
    if (_assertionMethod.remove(verificationMethodId)) {
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
    if (_authentication.remove(verificationMethodId)) {
      await store.removeAuthentication(verificationMethodId);
    }
    if (_keyAgreement.remove(verificationMethodId)) {
      await store.removeKeyAgreement(verificationMethodId);
    }
    if (_capabilityInvocation.remove(verificationMethodId)) {
      await store.removeCapabilityInvocation(verificationMethodId);
    }
    if (_capabilityDelegation.remove(verificationMethodId)) {
      await store.removeCapabilityDelegation(verificationMethodId);
    }
    if (_assertionMethod.remove(verificationMethodId)) {
      await store.removeAssertionMethod(verificationMethodId);
    }
  }

  /// Protected method to clear all verification method references.
  /// This is intended for use by subclasses that need to manage their own verification methods.
  Future<void> clearAllVerificationMethodReferences() async {
    _authentication.clear();
    _keyAgreement.clear();
    _capabilityInvocation.clear();
    _capabilityDelegation.clear();
    _assertionMethod.clear();
    await store.clearVerificationMethodReferences();
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
    final walletKeyId = await _getWalletKeyId(verificationMethodId);
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
    final walletKeyId = await _getWalletKeyId(verificationMethodId);
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

    final walletKeyId = await _getWalletKeyId(verificationMethodId);
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
    final walletKeyId = await _getWalletKeyId(verificationMethodId);
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

  // TODO: this should not be part of the did controller but of the key pairs themselves. Same can be said about the DidSigner
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
}
