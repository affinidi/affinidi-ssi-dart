import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import 'did_document/did_document.dart';
import 'did_key.dart';
import 'did_manager.dart';

/// DID Manager implementation for the did:key method.
///
/// This manager handles DID documents that use the did:key method,
/// which supports only a single public key per DID.
class DidKeyManager extends DidManager {
  PublicKey? _currentPublicKey;

  /// Creates a new DID Key manager instance.
  ///
  /// [keyMapping] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  /// [document] - An optional existing DID document to manage.
  DidKeyManager({
    required super.keyMapping,
    required super.wallet,
    super.document,
  });

  DidDocument _createDidDocumentFromState() {
    if (_currentPublicKey == null) {
      throw SsiException(
        message: 'DidKeyManager requires a public key to create a document. '
            'Use createDidDocumentFromKey() instead.',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
    return DidKey.generateDocument(_currentPublicKey!);
  }

  /// Creates a DID document from a single public key.
  ///
  /// [publicKey] - The public key to use for the DID document.
  ///
  /// Returns the created DID document.
  DidDocument createDidDocumentFromKey(PublicKey publicKey) {
    _currentPublicKey = publicKey;
    final doc = _createDidDocumentFromState();
    setDocument(doc);
    return doc;
  }

  @override
  Future<String> createVerificationMethod(
    KeyType keyType, {
    String? keyId,
    SignatureScheme? signatureScheme,
    bool useJwtThumbprint = false,
  }) async {
    final walletKeyId = keyId ??
        (useJwtThumbprint
            ? await generateJwtThumbprintKeyId(keyType)
            : generateKeyId());
    final keyPair = await wallet.generateKey(
      keyId: walletKeyId,
      keyType: keyType,
    );

    _currentPublicKey = keyPair.publicKey;
    final didDocument = _createDidDocumentFromState();
    final verificationMethodId = didDocument.verificationMethod.first.id;

    keyMapping.setMapping(verificationMethodId, walletKeyId);
    setDocument(didDocument);

    return verificationMethodId;
  }

  @override
  Future<String> addVerificationMethod(
    KeyType keyType,
    String walletKeyId, {
    SignatureScheme? signatureScheme,
  }) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);
    _currentPublicKey = publicKey;
    final didDocument = _createDidDocumentFromState();
    final verificationMethodId = didDocument.verificationMethod.first.id;

    keyMapping.setMapping(verificationMethodId, walletKeyId);
    setDocument(didDocument);

    return verificationMethodId;
  }
}
