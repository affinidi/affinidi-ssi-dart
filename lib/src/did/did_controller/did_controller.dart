import 'dart:convert';
import 'dart:typed_data';

import '../../digest_utils.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/key_pair.dart';
import '../../key_pair/public_key.dart';
import '../../types.dart';
import '../../util/base64_util.dart';
import '../../wallet/persistent_wallet.dart';
import '../../wallet/wallet.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint.dart';
import '../did_document/verification_method.dart';
import '../did_signer.dart';
import '../public_key_utils.dart';
import 'stores/did_controller_store.dart';

/// Base class for managing DID documents and their associated verification methods.
///
/// This abstract class provides shared functionality for creating and managing
/// DID documents with multiple verification methods, handling the mapping
/// between DID key identifiers and wallet key identifiers, and providing
/// signing and verification capabilities.
abstract class DidController {
  /// The key mapping store for this controller.
  final DidStore store;

  /// All verification methods
  final List<VerificationMethod> _verificationMethod = [];

  /// Verification methods for authentication purposes
  final List<String> authentication = [];

  /// Verification methods for key agreement purposes
  final List<String> keyAgreement = [];

  /// Verification methods for capability invocation purposes
  final List<String> capabilityInvocation = [];

  /// Verification methods for capability delegation purposes
  final List<String> capabilityDelegation = [];

  /// Verification methods for assertion purposes
  final List<String> assertionMethod = [];

  /// Verification methods for assertion purposes
  final List<ServiceEndpoint> _services = [];

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
        ...authentication,
      ],
      assertionMethod: [
        ...baseDocument.assertionMethod,
        ...assertionMethod,
      ],
      keyAgreement: [
        ...baseDocument.keyAgreement,
        ...keyAgreement,
      ],
      capabilityInvocation: [
        ...baseDocument.capabilityInvocation,
        ...capabilityInvocation,
      ],
      capabilityDelegation: [
        ...baseDocument.capabilityDelegation,
        ...capabilityDelegation,
      ],
      service: baseDocument.service,
    );
  }

  /// Add a service endpoint for the DID document.
  void addServiceEndpoint(ServiceEndpoint endpoint) {
    // TODO
    // Check that the id doesnt exist already and add the service endpoint
  }

  /// Remove a service endpoint from the DID document.
  void removeServiceEndpoint() {
    // What can be passed as a parameter to identify the endpoint to remove?
    // TODO
  }

  /// Creates or updates the DID document based on current state.
  /// Subclasses implement this to handle method-specific document creation.
  Future<DidDocument> createOrUpdateDocument();

  /// Finds the verification method ID for a given public key.
  /// Subclasses implement this to handle method-specific ID lookup.
  Future<String> findVerificationMethodId(PublicKey publicKey);

  /// Adds a verification method using an existing key from the wallet.
  Future<String> addVerificationMethod(String walletKeyId) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    final verificationMethodId = await findVerificationMethodId(publicKey);
    store.setMapping(verificationMethodId, walletKeyId);
    return verificationMethodId;
  }

  /// Adds an existing verification method reference to authentication.
  void addAuthentication(String verificationMethodId) {
    final walletKeyId = store.getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }
    authentication.add(verificationMethodId);
  }

  /// Adds an existing verification method reference to key agreement.
  void addKeyAgreement(String verificationMethodId) {
    final walletKeyId = store.getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }
    keyAgreement.add(verificationMethodId);
  }

  /// Adds an existing verification method reference to capability invocation.
  void addCapabilityInvocation(String verificationMethodId) {
    final walletKeyId = store.getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }
    capabilityInvocation.add(verificationMethodId);
  }

  /// Adds an existing verification method reference to capability delegation.
  void addCapabilityDelegation(String verificationMethodId) {
    final walletKeyId = store.getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }
    capabilityDelegation.add(verificationMethodId);
  }

  /// Adds an existing verification method reference to assertion method.
  void addAssertionMethod(String verificationMethodId) {
    final walletKeyId = store.getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
        message:
            'Verification method $verificationMethodId not found in mapping',
        code: SsiExceptionType.keyNotFound.code,
      );
    }
    assertionMethod.add(verificationMethodId);
  }

  /// Removes a verification method reference from authentication.
  void removeAuthentication(String verificationMethodId) {
    authentication.remove(verificationMethodId);
  }

  /// Removes a verification method reference from key agreement.
  void removeKeyAgreement(String verificationMethodId) {
    keyAgreement.remove(verificationMethodId);
  }

  /// Removes a verification method reference from capability invocation.
  void removeCapabilityInvocation(String verificationMethodId) {
    capabilityInvocation.remove(verificationMethodId);
  }

  /// Removes a verification method reference from capability delegation.
  void removeCapabilityDelegation(String verificationMethodId) {
    capabilityDelegation.remove(verificationMethodId);
  }

  /// Removes a verification method reference from assertion method.
  void removeAssertionMethod(String verificationMethodId) {
    assertionMethod.remove(verificationMethodId);
  }

  /// Removes a verification method reference from all verification relationships.
  void removeAllVerificationMethodReferences(String verificationMethodId) {
    authentication.remove(verificationMethodId);
    keyAgreement.remove(verificationMethodId);
    capabilityInvocation.remove(verificationMethodId);
    capabilityDelegation.remove(verificationMethodId);
    assertionMethod.remove(verificationMethodId);
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
    final walletKeyId = store.getWalletKeyId(verificationMethodId);
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
    final walletKeyId = store.getWalletKeyId(verificationMethodId);
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

    final walletKeyId = store.getWalletKeyId(verificationMethodId);
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

  /// Computes a JWT thumbprint for a given public key.
  ///
  /// Creates a JWK thumbprint based on RFC 7638 specification.
  /// This follows the exact steps defined in the RFC:
  /// 1. Construct JSON object with only required JWK members
  /// 2. Order members lexicographically
  /// 3. Hash UTF-8 octets with SHA-256
  ///
  /// [publicKeyBytes] - The public key bytes to compute thumbprint for.
  /// [keyType] - The key type.
  ///
  /// Returns a base64url-encoded JWT thumbprint.
  String computeJwtThumbprint(Uint8List publicKeyBytes, KeyType keyType) {
    final multikey = toMultikey(publicKeyBytes, keyType);
    final publicKeyJwk = multiKeyToJwk(multikey);

    // RFC 7638: Use only required members, ordered lexicographically
    final sortedKeys = Map.fromEntries(
        publicKeyJwk.entries.toList()..sort((a, b) => a.key.compareTo(b.key)));

    // RFC 7638: JSON with no whitespace, UTF-8 encode, then hash
    final canonicalJson = jsonEncode(sortedKeys);
    final thumbprintBytes = utf8.encode(canonicalJson);
    final hashedBytes = DigestUtils.getDigest(thumbprintBytes,
        hashingAlgorithm: HashingAlgorithm.sha256);

    return base64UrlNoPadEncode(hashedBytes);
  }

  /// Generates a JWT thumbprint-based key identifier.
  ///
  /// Creates a key identifier based on the JWT thumbprint specification (RFC 7638).
  /// This provides a standardized and deterministic way to generate key IDs.
  ///
  /// [keyType] - The key type to generate a thumbprint for.
  ///
  /// Returns a JWT thumbprint-based key identifier.
  Future<String> generateJwtThumbprintKeyId(KeyType keyType) async {
    final tempKeyPair = await wallet.generateKey(keyType: keyType);
    final thumbprint =
        computeJwtThumbprint(tempKeyPair.publicKey.bytes, keyType);
    return 'key-$thumbprint';
  }
}
