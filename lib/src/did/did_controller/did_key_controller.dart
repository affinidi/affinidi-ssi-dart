import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint.dart';
import '../did_key.dart';
import '../public_key_utils.dart';
import 'did_controller.dart';

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
  Future<String> addVerificationMethod(String walletKeyId) async {
    final verificationMethods = await store.verificationMethodIds;
    if (verificationMethods.isNotEmpty) {
      throw SsiException(
        message: 'did:key method supports only one key.',
        code: SsiExceptionType.unsupportedNumberOfKeys.code,
      );
    }
    return super.addVerificationMethod(walletKeyId);
  }

  Future<String> _getKeyId() async {
    final verificationMethods = await store.verificationMethodIds;
    if (verificationMethods.length != 1) {
      throw SsiException(
          message: 'DidKey expects a single key.',
          code: SsiExceptionType.unsupportedNumberOfKeys.code);
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
  Future<String> buildVerificationMethodId(PublicKey publicKey) async {
    // For did:key, the DID itself is derived from the public key.
    final multikey = toMultikey(publicKey.bytes, publicKey.type);
    final multibase = toMultiBase(multikey);
    final did = 'did:key:$multibase';

    // The verification method ID fragment is also derived from the same key.
    return '$did#$multibase';
  }

  @override
  Future<void> addAuthentication(String verificationMethodId) async {
    throw UnsupportedError(
        'Adding authentication verification methods to did:key method is not supported.');
  }

  @override
  Future<void> addKeyAgreement(String verificationMethodId) async {
    throw UnsupportedError(
        'Adding key agreement verification methods to did:key method is not supported.');
  }

  @override
  Future<void> addCapabilityInvocation(String verificationMethodId) async {
    throw UnsupportedError(
        'Adding capability invocation verification methods to did:key method is not supported.');
  }

  @override
  Future<void> addCapabilityDelegation(String verificationMethodId) async {
    throw UnsupportedError(
        'Adding capability delegation verification methods to did:key method is not supported.');
  }

  @override
  Future<void> addAssertionMethod(String verificationMethodId) async {
    throw UnsupportedError(
        'Adding assertion method verification methods to did:key method is not supported.');
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
