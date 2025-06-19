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
import '../did_key_pair.dart';
import '../did_signer.dart';
import '../public_key_utils.dart';
import 'did_controller_store.dart';

/// Enumeration of verification method purposes as defined by W3C DID specification.
///
/// This enum represents the different verification relationships that can be
/// established in a DID document. Each purpose defines how a verification method
/// can be used within the DID context.
enum VerificationMethodPurpose {
  /// Authentication verification methods are used to authenticate the DID subject.
  authentication,

  /// Key agreement verification methods are used for key agreement protocols
  /// such as ECDH (Elliptic Curve Diffie-Hellman).
  keyAgreement,

  /// Capability invocation verification methods are used to invoke capabilities
  /// or perform actions on behalf of the DID subject.
  capabilityInvocation,

  /// Capability delegation verification methods are used to delegate capabilities
  /// to other entities.
  capabilityDelegation,

  /// Assertion method verification methods are used for issuing verifiable credentials
  /// and other assertions.
  assertionMethod,

  /// Custom verification method purpose for non-standard use cases.
  /// When using this value, provide the custom purpose string separately.
  custom;

  /// Converts the enum value to its string representation for use in DID documents.
  String get value {
    switch (this) {
      case VerificationMethodPurpose.authentication:
        return 'authentication';
      case VerificationMethodPurpose.keyAgreement:
        return 'keyAgreement';
      case VerificationMethodPurpose.capabilityInvocation:
        return 'capabilityInvocation';
      case VerificationMethodPurpose.capabilityDelegation:
        return 'capabilityDelegation';
      case VerificationMethodPurpose.assertionMethod:
        return 'assertionMethod';
      case VerificationMethodPurpose.custom:
        return 'custom';
    }
  }

  /// Creates a VerificationMethodPurpose from its string representation.
  static VerificationMethodPurpose fromString(String value) {
    switch (value) {
      case 'authentication':
        return VerificationMethodPurpose.authentication;
      case 'keyAgreement':
        return VerificationMethodPurpose.keyAgreement;
      case 'capabilityInvocation':
        return VerificationMethodPurpose.capabilityInvocation;
      case 'capabilityDelegation':
        return VerificationMethodPurpose.capabilityDelegation;
      case 'assertionMethod':
        return VerificationMethodPurpose.assertionMethod;
      default:
        return VerificationMethodPurpose.custom;
    }
  }
}

/// Base class for managing DID documents and their associated verification methods.
///
/// This abstract class provides shared functionality for creating and managing
/// DID documents with multiple verification methods, handling the mapping
/// between DID key identifiers and wallet key identifiers, and providing
/// signing and verification capabilities.
abstract class DidController {
  /// The key mapping store for this controller.
  final DiDControllerStore keyMapping;

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

  /// The wallet instance for key operations.
  final Wallet wallet;

  /// Creates a new DID controller instance.
  ///
  /// [keyMapping] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidController({
    required this.keyMapping,
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

  /// Creates a new authentication verification method with a new key.
  Future<String> createAuthenticationVerificationMethod(
    KeyType keyType, {
    String? keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final walletKeyId = keyId ?? await generateKeyId(keyType);
    final keyPair = await wallet.generateKey(
      keyId: walletKeyId,
      keyType: keyType,
    );

    addAuthenticationKey(keyPair.publicKey);
    final verificationMethodId =
        await findVerificationMethodId(keyPair.publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    authentication.add(verificationMethodId);

    return verificationMethodId;
  }

  /// Creates a new key agreement verification method with a new key.
  Future<String> createKeyAgreementVerificationMethod(
    KeyType keyType, {
    String? keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final walletKeyId = keyId ?? await generateKeyId(keyType);
    final keyPair = await wallet.generateKey(
      keyId: walletKeyId,
      keyType: keyType,
    );

    addKeyAgreementKey(keyPair.publicKey);
    final verificationMethodId =
        await findVerificationMethodId(keyPair.publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    keyAgreement.add(verificationMethodId);

    return verificationMethodId;
  }

  /// Creates a new capability invocation verification method with a new key.
  Future<String> createCapabilityInvocationVerificationMethod(
    KeyType keyType, {
    String? keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final walletKeyId = keyId ?? await generateKeyId(keyType);
    final keyPair = await wallet.generateKey(
      keyId: walletKeyId,
      keyType: keyType,
    );

    addCapabilityInvocationKey(keyPair.publicKey);
    final verificationMethodId =
        await findVerificationMethodId(keyPair.publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    capabilityInvocation.add(verificationMethodId);

    return verificationMethodId;
  }

  /// Creates a new capability delegation verification method with a new key.
  Future<String> createCapabilityDelegationVerificationMethod(
    KeyType keyType, {
    String? keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final walletKeyId = keyId ?? await generateKeyId(keyType);
    final keyPair = await wallet.generateKey(
      keyId: walletKeyId,
      keyType: keyType,
    );

    addCapabilityDelegationKey(keyPair.publicKey);
    final verificationMethodId =
        await findVerificationMethodId(keyPair.publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    capabilityDelegation.add(verificationMethodId);

    return verificationMethodId;
  }

  /// Creates a new assertion method verification method with a new key.
  Future<String> createAssertionMethodVerificationMethod(
    KeyType keyType, {
    String? keyId,
    SignatureScheme? signatureScheme,
  }) async {
    final walletKeyId = keyId ?? await generateKeyId(keyType);
    final keyPair = await wallet.generateKey(
      keyId: walletKeyId,
      keyType: keyType,
    );

    addAssertionMethodKey(keyPair.publicKey);
    final verificationMethodId =
        await findVerificationMethodId(keyPair.publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    assertionMethod.add(verificationMethodId);

    return verificationMethodId;
  }

  /// Adds a key for authentication purposes to the DID method-specific storage.
  void addAuthenticationKey(PublicKey publicKey);

  /// Adds a key for key agreement purposes to the DID method-specific storage.
  void addKeyAgreementKey(PublicKey publicKey);

  /// Adds a key for capability invocation purposes to the DID method-specific storage.
  void addCapabilityInvocationKey(PublicKey publicKey);

  /// Adds a key for capability delegation purposes to the DID method-specific storage.
  void addCapabilityDelegationKey(PublicKey publicKey);

  /// Adds a key for assertion method purposes to the DID method-specific storage.
  void addAssertionMethodKey(PublicKey publicKey);

  /// Creates or updates the DID document based on current state.
  /// Subclasses implement this to handle method-specific document creation.
  Future<DidDocument> createOrUpdateDocument();

  /// Finds the verification method ID for a given public key.
  /// Subclasses implement this to handle method-specific ID lookup.
  Future<String> findVerificationMethodId(PublicKey publicKey);

  /// Adds an authentication verification method using an existing key from the wallet.
  Future<String> addAuthenticationVerificationMethod(
    KeyType keyType,
    String walletKeyId, {
    SignatureScheme? signatureScheme,
  }) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    addAuthenticationKey(publicKey);
    final verificationMethodId = await findVerificationMethodId(publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    authentication.add(verificationMethodId);
    return verificationMethodId;
  }

  /// Adds a key agreement verification method using an existing key from the wallet.
  Future<String> addKeyAgreementVerificationMethod(
    KeyType keyType,
    String walletKeyId, {
    SignatureScheme? signatureScheme,
  }) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    addKeyAgreementKey(publicKey);
    final verificationMethodId = await findVerificationMethodId(publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    keyAgreement.add(verificationMethodId);
    return verificationMethodId;
  }

  /// Adds a capability invocation verification method using an existing key from the wallet.
  Future<String> addCapabilityInvocationVerificationMethod(
    KeyType keyType,
    String walletKeyId, {
    SignatureScheme? signatureScheme,
  }) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    addCapabilityInvocationKey(publicKey);
    final verificationMethodId = await findVerificationMethodId(publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    capabilityInvocation.add(verificationMethodId);
    return verificationMethodId;
  }

  /// Adds a capability delegation verification method using an existing key from the wallet.
  Future<String> addCapabilityDelegationVerificationMethod(
    KeyType keyType,
    String walletKeyId, {
    SignatureScheme? signatureScheme,
  }) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    addCapabilityDelegationKey(publicKey);
    final verificationMethodId = await findVerificationMethodId(publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    capabilityDelegation.add(verificationMethodId);
    return verificationMethodId;
  }

  /// Adds an assertion method verification method using an existing key from the wallet.
  Future<String> addAssertionMethodVerificationMethod(
    KeyType keyType,
    String walletKeyId, {
    SignatureScheme? signatureScheme,
  }) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    addAssertionMethodKey(publicKey);
    final verificationMethodId = await findVerificationMethodId(publicKey);
    keyMapping.setMapping(verificationMethodId, walletKeyId);
    assertionMethod.add(verificationMethodId);
    return verificationMethodId;
  }

  /// Adds an existing verification method reference to authentication.
  void addAuthenticationVerificationMethodReference(
      String verificationMethodId) {
    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
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
  void addKeyAgreementVerificationMethodReference(String verificationMethodId) {
    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
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
  void addCapabilityInvocationVerificationMethodReference(
      String verificationMethodId) {
    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
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
  void addCapabilityDelegationVerificationMethodReference(
      String verificationMethodId) {
    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
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
  void addAssertionMethodVerificationMethodReference(
      String verificationMethodId) {
    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
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
  void removeAuthenticationVerificationMethodReference(
      String verificationMethodId) {
    authentication.remove(verificationMethodId);
  }

  /// Removes a verification method reference from key agreement.
  void removeKeyAgreementVerificationMethodReference(
      String verificationMethodId) {
    keyAgreement.remove(verificationMethodId);
  }

  /// Removes a verification method reference from capability invocation.
  void removeCapabilityInvocationVerificationMethodReference(
      String verificationMethodId) {
    capabilityInvocation.remove(verificationMethodId);
  }

  /// Removes a verification method reference from capability delegation.
  void removeCapabilityDelegationVerificationMethodReference(
      String verificationMethodId) {
    capabilityDelegation.remove(verificationMethodId);
  }

  /// Removes a verification method reference from assertion method.
  void removeAssertionMethodVerificationMethodReference(
      String verificationMethodId) {
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
    final didDocument = await getDidDocument();

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
    final walletKeyId = keyMapping.getWalletKeyId(verificationMethodId);
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

  /// Generates a key identifier using JWT thumbprint.
  Future<String> generateKeyId(KeyType keyType) async {
    return await generateJwtThumbprintKeyId(keyType);
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
