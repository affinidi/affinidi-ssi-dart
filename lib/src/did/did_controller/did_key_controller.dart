import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../did_document/did_document.dart';
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

  Future<DidDocument> _createDidDocumentFromState() async {
    final keyId = _getKeyId();
    final key = await wallet.getPublicKey(keyId);
    return DidKey.generateDocument(key);
  }

  String _getKeyId() {
    if (verificationMethodKeys.length != 1) {
      throw SsiException(
          message: 'DidKey expects a single key.',
          code: SsiExceptionType.unsupportedNumberOfKeys.code);
    }
    return verificationMethodKeys.first;
  }

  // DidKeyController now uses the base class implementation for addXXX methods

  @override
  Future<DidDocument> createOrUpdateDocument() async {
    // For did:key, clear the base controller arrays to avoid duplicates
    // since the DID document generation already includes the verification methods
    clearAllVerificationMethodReferences();

    return await _createDidDocumentFromState();
  }

  @override
  Future<String> buildVerificationMethodId(String keyId) async {
    // 1. Validate the provided keyId
    final storedKeyId = _getKeyId();
    if (storedKeyId != keyId) {
      throw SsiException(
          message: 'Provided keyId not found',
          code: SsiExceptionType.keyNotFound.code);
    }

    // 2. Resolve the controller DID from the *single* key.
    final key = await wallet.getPublicKey(storedKeyId);
    final multikey = toMultikey(key.bytes, key.type);
    final multibase = toMultiBase(multikey);
    final did = 'did:key:$multibase';

    // 3. Encode the queried key for the fragment.
    final publicKey = await wallet.getPublicKey(storedKeyId);
    final fragmentMultikey = toMultikey(publicKey.bytes, publicKey.type);
    final fragmentMultibase = toMultiBase(fragmentMultikey);

    // 4. Return full verification‑method ID.
    return '$did#$fragmentMultibase';
  }

  @override
  void addAuthentication(String verificationMethodId) {
    throw UnsupportedError(
        'Adding authentication verification methods to did:key method is not supported.');
  }

  @override
  void addKeyAgreement(String verificationMethodId) {
    throw UnsupportedError(
        'Adding key agreement verification methods to did:key method is not supported.');
  }

  @override
  void addCapabilityInvocation(String verificationMethodId) {
    throw UnsupportedError(
        'Adding capability invocation verification methods to did:key method is not supported.');
  }

  @override
  void addCapabilityDelegation(String verificationMethodId) {
    throw UnsupportedError(
        'Adding capability delegation verification methods to did:key method is not supported.');
  }

  @override
  void addAssertionMethod(String verificationMethodId) {
    throw UnsupportedError(
        'Adding assertion method verification methods to did:key method is not supported.');
  }
}
