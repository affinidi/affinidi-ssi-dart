import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../../types.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint.dart';
import '../did_key.dart';
import '../did_web.dart';
import 'add_verification_method_result.dart';
import 'did_manager.dart';
import 'verification_relationship.dart';

/// DID Manager implementation for the did:key method.
///
/// This manager handles DID documents that use the did:key method,
/// which supports only a single public key per DID.
class DidWebManager extends DidManager {
  /// Creates a new DID Key manager instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidWebManager({required super.store, required super.wallet});

  @override
  Future<AddVerificationMethodResult> addVerificationMethod(
    String walletKeyId, {
    Set<VerificationRelationship>? relationships,
  }) async {
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

  Future<List<String>> _getKeyIds() async {
    final verificationMethods = await store.verificationMethodIds;
    if (verificationMethods.isEmpty) {
      throw SsiException(
        message: 'did:web method expects at least one key to be present.',
        code: SsiExceptionType.verificationMethodNotFound.code,
      );
    }

    final walletKeyIds = <String>[];
    for (final verificationMethodId in verificationMethods) {
      final walletKeyId = await getWalletKeyId(verificationMethodId);
      if (walletKeyId == null) {
        throw SsiException(
          message:
              'Wallet key for verification method $verificationMethodId not found.',
          code: SsiExceptionType.keyNotFound.code,
        );
      }
      walletKeyIds.add(walletKeyId);
    }

    return walletKeyIds;
  }

  @override
  Future<DidDocument> getDidDocument() async {
    final keyIds = await _getKeyIds();
    final publicKeys = await Future.wait(keyIds.map(
      (keyId) async => await wallet.getPublicKey(keyId),
    ));

    final relationships = {
      VerificationRelationship.authentication: authentication.toList(),
      VerificationRelationship.keyAgreement: keyAgreement.toList(),
      VerificationRelationship.assertionMethod: assertionMethod.toList(),
    };

    final service = await store.serviceEndpoints;

    final vms = await store.verificationMethodIds;
    return DidWeb.generateDocument(
      did: publicKeys[0].id.split('#')[0],
      verificationMethodIds: vms,
      publicKeys: publicKeys,
      relationships: relationships,
      serviceEndpoints: service,
    );
  }

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey) async {
    return publicKey.id;
  }
}
