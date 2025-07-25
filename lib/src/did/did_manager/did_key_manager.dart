import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../../types.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint.dart';
import '../did_key.dart';
import '../public_key_utils.dart';
import 'add_verification_method_result.dart';
import 'did_manager.dart';
import 'verification_relationship.dart';

/// DID Manager implementation for the did:key method.
///
/// This manager handles DID documents that use the did:key method,
/// which supports only a single public key per DID.
class DidKeyManager extends DidManager {
  /// Creates a new DID Key manager instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidKeyManager({
    required super.store,
    required super.wallet,
  });

  @override
  Future<AddVerificationMethodResult> addVerificationMethod(
    String walletKeyId, {
    Set<VerificationRelationship>? relationships,
  }) async {
    final verificationMethods = await store.verificationMethodIds;
    if (verificationMethods.isNotEmpty) {
      throw SsiException(
        message: 'did:key method supports only one key.',
        code: SsiExceptionType.tooManyVerificationMethods.code,
      );
    }

    if (relationships != null) {
      throw SsiException(
        message: 'For did:key, relationships are automatically assigned and '
            'cannot be specified manually.',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }

    final result = await super.addVerificationMethod(walletKeyId);

    // For Ed25519 keys, we need to store the mapping for the derived X25519 key agreement method
    // that is created by DidKey.generateDocument()
    final publicKey = await wallet.getPublicKey(walletKeyId);
    if (publicKey.type == KeyType.ed25519) {
      await _mapX25519KeyAgreementMethod(walletKeyId);
    }

    return result;
  }

  /// Maps the X25519 key agreement method to the wallet key ID for Ed25519 keys
  Future<void> _mapX25519KeyAgreementMethod(String walletKeyId) async {
    final didDocument = await getDidDocument();

    // For did:key, there's always exactly one key agreement method
    if (didDocument.keyAgreement.isEmpty) {
      throw SsiException(
        message: 'No key agreement methods found in did:key document.',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    final x25519KeyAgreementMethod = didDocument.keyAgreement.first;

    // Store the mapping for the X25519 key agreement method
    await store.setMapping(x25519KeyAgreementMethod.id, walletKeyId);
  }

  Future<String> _getKeyId() async {
    final verificationMethods = await store.verificationMethodIds;
    if (verificationMethods.isEmpty) {
      throw SsiException(
        message: 'did:key method expects one key to be present.',
        code: SsiExceptionType.verificationMethodNotFound.code,
      );
    }
    final verificationMethodId = verificationMethods.first;
    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
          message:
              'Wallet key for verification method $verificationMethodId not found.',
          code: SsiExceptionType.keyNotFound.code);
    }
    return walletKeyId;
  }

  @override
  Future<DidDocument> getDidDocument() async {
    final keyId = await _getKeyId();
    final key = await wallet.getPublicKey(keyId);
    return DidKey.generateDocument(key);
  }

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey) async {
    // For did:key, the DID itself is derived from the public key.
    final didMultikey = toMultikey(publicKey.bytes, publicKey.type);
    final didMultibase = toMultiBase(didMultikey);
    final did = 'did:key:$didMultibase';

    // The verification method ID fragment is derived from the public key.
    final fragmentMultikey = toMultikey(publicKey.bytes, publicKey.type);
    final fragmentMultibase = toMultiBase(fragmentMultikey);
    return '$did#$fragmentMultibase';
  }

  @override
  Future<void> addAuthentication(String verificationMethodId) async {
    if (authentication.isNotEmpty) {
      throw UnsupportedError(
          'did:key does not support manually modifying verification relationships.');
    }
    return super.addAuthentication(verificationMethodId);
  }

  @override
  Future<void> addKeyAgreement(String verificationMethodId) async {
    if (keyAgreement.isNotEmpty) {
      throw UnsupportedError(
          'did:key does not support manually modifying verification relationships.');
    }
    return super.addKeyAgreement(verificationMethodId);
  }

  @override
  Future<void> addCapabilityInvocation(String verificationMethodId) async {
    if (capabilityInvocation.isNotEmpty) {
      throw UnsupportedError(
          'did:key does not support manually modifying verification relationships.');
    }
    return super.addCapabilityInvocation(verificationMethodId);
  }

  @override
  Future<void> addCapabilityDelegation(String verificationMethodId) async {
    if (capabilityDelegation.isNotEmpty) {
      throw UnsupportedError(
          'did:key does not support manually modifying verification relationships.');
    }
    return super.addCapabilityDelegation(verificationMethodId);
  }

  @override
  Future<void> addAssertionMethod(String verificationMethodId) async {
    if (assertionMethod.isNotEmpty) {
      throw UnsupportedError(
          'did:key does not support manually modifying verification relationships.');
    }
    return super.addAssertionMethod(verificationMethodId);
  }

  @override
  Future<void> addServiceEndpoint(ServiceEndpoint endpoint) async {
    throw UnsupportedError(
        'Adding service endpoints to did:key method is not supported.');
  }

  @override
  Future<void> removeServiceEndpoint(String id) async {
    throw UnsupportedError(
        'Removing service endpoints from did:key method is not supported.');
  }
}
