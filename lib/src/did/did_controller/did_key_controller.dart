import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../did_document/did_document.dart';
import '../did_key.dart';
import '../public_key_utils.dart';
import 'did_controller.dart';

/// DID Controller implementation for the did:key method.
///
/// This controller handles DID documents that use the did:key method,
/// which supports only a single public key per DID.
class DidKeyController extends DidController {
  final Map<VerificationMethodPurpose, List<PublicKey>> _keysByPurpose = {};

  /// Creates a new DID Key controller instance.
  ///
  /// [keyMapping] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidKeyController({
    required super.keyMapping,
    required super.wallet,
  });

  DidDocument _createDidDocumentFromState() {
    final primaryKey = _getPrimaryKey();
    if (primaryKey == null) {
      throw SsiException(
        message: 'DidKeyController requires a public key to create a document. '
            'Use createDidDocumentFromKey() instead.',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
    return DidKey.generateDocument(primaryKey);
  }

  PublicKey? _getPrimaryKey() {
    for (final keys in _keysByPurpose.values) {
      if (keys.isNotEmpty) {
        return keys.first;
      }
    }
    return null;
  }

  /// Creates a DID document from a single public key.
  ///
  /// [publicKey] - The public key to use for the DID document.
  /// [purpose] - The verification method purpose for this key.
  ///
  /// Returns the created DID document.
  DidDocument createDidDocumentFromKey(PublicKey publicKey,
      [VerificationMethodPurpose purpose =
          VerificationMethodPurpose.authentication]) {
    _keysByPurpose.putIfAbsent(purpose, () => []).add(publicKey);
    return _createDidDocumentFromState();
  }

  @override
  void addAuthenticationKey(PublicKey publicKey) {
    _keysByPurpose
        .putIfAbsent(VerificationMethodPurpose.authentication, () => [])
        .add(publicKey);
  }

  @override
  void addKeyAgreementKey(PublicKey publicKey) {
    _keysByPurpose
        .putIfAbsent(VerificationMethodPurpose.keyAgreement, () => [])
        .add(publicKey);
  }

  @override
  void addCapabilityInvocationKey(PublicKey publicKey) {
    _keysByPurpose
        .putIfAbsent(VerificationMethodPurpose.capabilityInvocation, () => [])
        .add(publicKey);
  }

  @override
  void addCapabilityDelegationKey(PublicKey publicKey) {
    _keysByPurpose
        .putIfAbsent(VerificationMethodPurpose.capabilityDelegation, () => [])
        .add(publicKey);
  }

  @override
  void addAssertionMethodKey(PublicKey publicKey) {
    _keysByPurpose
        .putIfAbsent(VerificationMethodPurpose.assertionMethod, () => [])
        .add(publicKey);
  }

  @override
  Future<DidDocument> createOrUpdateDocument() async {
    // For did:key, clear the base controller arrays to avoid duplicates
    // since the DID document generation already includes the verification methods
    authentication.clear();
    assertionMethod.clear();
    keyAgreement.clear();
    capabilityInvocation.clear();
    capabilityDelegation.clear();

    return _createDidDocumentFromState();
  }

  @override
  Future<String> findVerificationMethodId(PublicKey publicKey) async {
    // 1. Resolve the controller DID from the *primary* key.
    final primaryKey = _getPrimaryKey();
    if (primaryKey == null) {
      throw SsiException(
        message: 'No primary key set. cannot derrive DID.',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    final primaryMultikey = toMultikey(primaryKey.bytes, primaryKey.type);
    final primaryMultibase = toMultiBase(primaryMultikey);
    final did = 'did:key:$primaryMultibase';

    // 2. Encode the queried key for the fragment.
    final fragmentMultikey = toMultikey(publicKey.bytes, publicKey.type);
    final fragmentMultibase = toMultiBase(fragmentMultikey);

    // 3. Return full verification‑method ID.
    return '$did#$fragmentMultibase';
  }
}
