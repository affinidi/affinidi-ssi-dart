import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint.dart';
import '../did_key.dart';
import '../public_key_utils.dart';
import 'add_verification_method_result.dart';
import 'did_controller.dart';
import 'verification_relationship.dart';

/// DID Controller implementation for the did:key method.
///
/// This controller handles DID documents that use the did:key method,
/// which supports only a single public key per DID.
class DidKeyController extends DidController {
  /// Creates a new DID Key controller instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidKeyController({
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
        code: SsiExceptionType.unsupportedNumberOfKeys.code,
      );
    }

    if (relationships != null) {
      throw SsiException(
        message: 'For did:key, relationships are automatically assigned and '
            'cannot be specified manually.',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }

    return super.addVerificationMethod(walletKeyId);
  }

  Future<String> _getKeyId() async {
    final verificationMethods = await store.verificationMethodIds;
    if (verificationMethods.isEmpty) {
      throw SsiException(
        message: 'DidKey expects a single key.',
        code: SsiExceptionType.unsupportedNumberOfKeys.code,
      );
    }
    final verificationMethodId = verificationMethods.first;
    final walletKeyId = await getWalletKeyId(verificationMethodId);
    if (walletKeyId == null) {
      throw SsiException(
          message:
              'Wallet key for verification method $verificationMethodId not found',
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
  Future<String> buildVerificationMethodId(PublicKey publicKey, {PublicKey? primaryPublicKey}) async {
    // For did:key, the DID itself is derived from the public key.
    final didKey = primaryPublicKey ?? publicKey;
    final didMultikey = toMultikey(didKey.bytes, didKey.type);
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
