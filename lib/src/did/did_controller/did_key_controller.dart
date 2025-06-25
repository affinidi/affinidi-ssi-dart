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
  /// [keyMapping] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidKeyController({
    required super.keyMapping,
    required super.wallet,
  });

  Future<DidDocument> _createDidDocumentFromState() async {
    final primaryKeyId = _getPrimaryKeyId();
    if (primaryKeyId == null) {
      throw SsiException(
        message: 'DidKeyController requires a key ID to create a document. '
            'Use createDidDocumentFromKey() instead.',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
    final primaryKey = await wallet.getPublicKey(primaryKeyId);
    return DidKey.generateDocument(primaryKey);
  }

  String? _getPrimaryKeyId() {
    for (final keyIds in keysByPurpose.values) {
      if (keyIds.isNotEmpty) {
        return keyIds.first;
      }
    }
    return null;
  }

  /// Creates a DID document from a single key ID.
  ///
  /// [keyId] - The key ID to use for the DID document.
  /// [purpose] - The verification method purpose for this key.
  ///
  /// Returns the created DID document.
  Future<DidDocument> createDidDocumentFromKey(String keyId,
      [VerificationMethodPurpose purpose =
          VerificationMethodPurpose.authentication]) async {
    keysByPurpose.putIfAbsent(purpose, () => []).add(keyId);
    return await _createDidDocumentFromState();
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
  Future<String> findVerificationMethodId(String keyId) async {
    // 1. Resolve the controller DID from the *primary* key.
    final primaryKeyId = _getPrimaryKeyId();
    if (primaryKeyId == null) {
      throw SsiException(
        message: 'No primary key set. cannot derive DID.',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    final primaryKey = await wallet.getPublicKey(primaryKeyId);
    final primaryMultikey = toMultikey(primaryKey.bytes, primaryKey.type);
    final primaryMultibase = toMultiBase(primaryMultikey);
    final did = 'did:key:$primaryMultibase';

    // 2. Encode the queried key for the fragment.
    final publicKey = await wallet.getPublicKey(keyId);
    final fragmentMultikey = toMultikey(publicKey.bytes, publicKey.type);
    final fragmentMultibase = toMultiBase(fragmentMultikey);

    // 3. Return full verification‑method ID.
    return '$did#$fragmentMultibase';
  }
}
