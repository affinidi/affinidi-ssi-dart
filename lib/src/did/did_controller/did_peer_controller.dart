import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../../types.dart';
import '../../utility.dart';
import '../did_document/did_document.dart';
import '../did_peer.dart';
import 'did_controller.dart';
import 'verification_relationship.dart';

/// DID Controller implementation for the did:peer method.
///
/// This controller handles DID documents that use the did:peer method,
/// which supports multiple keys with separate authentication and
/// key agreement purposes, as well as service endpoints.
class DidPeerController extends DidController {
  /// Creates a new DID Peer controller instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidPeerController({
    required super.store,
    required super.wallet,
  });

  @override
  Future<DidDocument> getDidDocument() async {
    if (authentication.isEmpty &&
        keyAgreement.isEmpty &&
        assertionMethod.isEmpty &&
        capabilityInvocation.isEmpty &&
        capabilityDelegation.isEmpty) {
      throw SsiException(
        message:
            'At least one key must be added before creating did:peer document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Create a master list of unique verification method IDs.
    final uniqueVmIds = {
      ...authentication,
      ...keyAgreement,
      ...assertionMethod,
      ...capabilityInvocation,
      ...capabilityDelegation
    }.toList();

    // Create a list of public keys for each unique verification method.
    // This handles cases like an Ed25519 key being used for signing and its
    // converted X25519 form for key agreement.
    final verificationMethods = <PublicKey>[];
    for (final vmId in uniqueVmIds) {
      final walletKeyId = await getWalletKeyId(vmId);
      if (walletKeyId == null) {
        throw SsiException(
            message: 'Could not find wallet key for $vmId',
            code: SsiExceptionType.keyNotFound.code);
      }

      var publicKey = await wallet.getPublicKey(walletKeyId);
      if (keyAgreement.contains(vmId) && publicKey.type == KeyType.ed25519) {
        final x25519PublicKeyBytes =
            ed25519PublicToX25519Public(publicKey.bytes);
        publicKey =
            PublicKey(publicKey.id, x25519PublicKeyBytes, KeyType.x25519);
      }
      verificationMethods.add(publicKey);
    }

    // Create a map from verification method ID to its index in the list.
    final vmIdToIndex = <String, int>{
      for (var i = 0; i < uniqueVmIds.length; i++) uniqueVmIds[i]: i
    };

    // For each relationship, create a list of key indices.
    List<int> getIndexes(Iterable<String> vmIds) {
      return vmIds.map((vmId) => vmIdToIndex[vmId]!).toSet().toList();
    }

    final relationships = {
      VerificationRelationship.authentication: getIndexes(authentication),
      VerificationRelationship.keyAgreement: getIndexes(keyAgreement),
      VerificationRelationship.assertionMethod: getIndexes(assertionMethod),
      VerificationRelationship.capabilityInvocation:
          getIndexes(capabilityInvocation),
      VerificationRelationship.capabilityDelegation:
          getIndexes(capabilityDelegation),
    };

    return DidPeer.generateDocument(
      verificationMethods: verificationMethods,
      relationships: relationships,
      serviceEndpoints: service.toList(),
    );
  }

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey,
      {PublicKey? primaryPublicKey}) async {
    // For did:peer, verification method IDs are numbered sequentially
    // based on their order in the verificationMethod array
    final verificationMethods = await store.verificationMethodIds;

    // Verification method IDs are 1-indexed
    return '#key-${verificationMethods.length + 1}';
  }
}
