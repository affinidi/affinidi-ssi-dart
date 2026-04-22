import 'package:meta/meta.dart';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../../types.dart';
import '../../utility.dart';
import '../did_document/did_document.dart';
import '../did_peer.dart';
import 'add_verification_method_result.dart';
import 'did_manager.dart';
import 'verification_relationship.dart';

/// DID Manager implementation for the did:peer method.
///
/// This manager handles DID documents that use the did:peer method,
/// which supports multiple keys with separate authentication and
/// key agreement purposes, as well as service endpoints.
class DidPeerManager extends DidManager {
  /// Creates a new DID Peer manager instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidPeerManager({
    required super.store,
    required super.wallet,
  });

  @override
  @protected
  Future<AddVerificationMethodResult> internalAddVerificationMethod(
    String walletKeyId, {
    required PublicKey publicKey,
    required Set<VerificationRelationship> relationships,
  }) async {
    final createdRelationships = <VerificationRelationship, String>{};
    String? primaryVmId;

    // If no relationships are specified, create one VM not attached to any purpose.
    if (relationships.isEmpty) {
      final vmId = await buildVerificationMethodId(publicKey);
      await store.setMapping(vmId, walletKeyId);
      return AddVerificationMethodResult(
        verificationMethodId: vmId,
        relationships: const {},
      );
    }

    // Define a fixed order for processing relationships to ensure consistent
    // DID generation, as the order of elements in a did:peer:2 DID is significant.
    const processingOrder = [
      VerificationRelationship.authentication,
      VerificationRelationship.keyAgreement,
      VerificationRelationship.capabilityInvocation,
      VerificationRelationship.capabilityDelegation,
      VerificationRelationship.assertionMethod,
    ];

    final orderedRelationships =
        processingOrder.where((r) => relationships.contains(r));

    for (final relationship in orderedRelationships) {
      final String vmId;
      // Special handling for keyAgreement with Ed25519 keys
      if (relationship == VerificationRelationship.keyAgreement &&
          publicKey.type == KeyType.ed25519) {
        final x25519PublicKeyBytes =
            ed25519PublicToX25519Public(publicKey.bytes);
        final keyAgreementPublicKey =
            PublicKey(publicKey.id, x25519PublicKeyBytes, KeyType.x25519);
        vmId = await buildVerificationMethodId(keyAgreementPublicKey);
      } else {
        vmId = await buildVerificationMethodId(publicKey);
      }

      await addVerificationMethodFromPublicKey(
        publicKey,
        verificationMethodId: vmId,
      );
      primaryVmId ??= vmId;

      switch (relationship) {
        case VerificationRelationship.authentication:
          await addAuthentication(vmId);
          break;
        case VerificationRelationship.assertionMethod:
          await addAssertionMethod(vmId);
          break;
        case VerificationRelationship.capabilityInvocation:
          await addCapabilityInvocation(vmId);
          break;
        case VerificationRelationship.capabilityDelegation:
          await addCapabilityDelegation(vmId);
          break;
        case VerificationRelationship.keyAgreement:
          await addKeyAgreement(vmId);
          break;
      }
      createdRelationships[relationship] = vmId;
    }

    return AddVerificationMethodResult(
      verificationMethodId: primaryVmId!,
      relationships: createdRelationships,
    );
  }

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

    // Get all verification method IDs in their creation order.
    final uniqueVmIds = await store.verificationMethodIds;

    // Create a list of public keys for each unique verification method.
    final verificationMethodsPubKeys = <PublicKey>[];
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
      verificationMethodsPubKeys.add(publicKey);
    }

    // Create a map from verification method ID to its index in the list.
    final vmIdToIndex = <String, int>{
      for (var i = 0; i < uniqueVmIds.length; i++) uniqueVmIds[i]: i
    };

    // For each relationship, create a list of key indices.
    List<int> getIndexes(Iterable<String> vmIds) {
      return vmIds.map((vmId) => vmIdToIndex[vmId]!).toList();
    }

    final relationshipIndexes = {
      VerificationRelationship.authentication: getIndexes(authentication),
      VerificationRelationship.keyAgreement: getIndexes(keyAgreement),
      VerificationRelationship.assertionMethod: getIndexes(assertionMethod),
      VerificationRelationship.capabilityInvocation:
          getIndexes(capabilityInvocation),
      VerificationRelationship.capabilityDelegation:
          getIndexes(capabilityDelegation),
    };

    final did = DidPeer.getDid(
      verificationMethods: verificationMethodsPubKeys,
      relationships: relationshipIndexes,
      serviceEndpoints: service.toList(),
    );

    // For did:peer:0, the resolution logic is simple and handles key derivation.
    if (DidPeer.determineType(did) == DidPeerType.peer0) {
      final doc = DidPeer.resolve(did);

      // did:peer:0 resolves to a did:key document where VM IDs use the
      // multibase key as fragment (e.g. #zDnaem...), but the store
      // has sequential #key-N IDs. Replace the old mappings with the
      // resolved multibase IDs so lookups by the new IDs succeed.
      // For peer:0, all VMs originate from a single wallet key.
      final walletKeyId = await getWalletKeyId(uniqueVmIds.first);
      if (walletKeyId != null) {
        // Remove the old sequential IDs and add resolved multibase IDs.
        for (final oldId in uniqueVmIds) {
          await store.removeMapping(oldId);
        }
        for (var i = 0; i < doc.verificationMethod.length; i++) {
          final resolvedFragment =
              '#${doc.verificationMethod[i].id.split('#').last}';
          await store.setMapping(resolvedFragment, walletKeyId);
        }

        // Update cached relationship lists to use resolved multibase IDs
        // so that callers (e.g. getSigner(authentication.first)) get IDs
        // that match the document.
        await clearVerificationMethodReferences();
        for (final vmId
            in doc.authentication.map((v) => '#${v.id.split('#').last}')) {
          await addAuthentication(vmId);
        }
        for (final vmId
            in doc.keyAgreement.map((v) => '#${v.id.split('#').last}')) {
          await addKeyAgreement(vmId);
        }
        for (final vmId
            in doc.assertionMethod.map((v) => '#${v.id.split('#').last}')) {
          await addAssertionMethod(vmId);
        }
        for (final vmId in doc.capabilityInvocation
            .map((v) => '#${v.id.split('#').last}')) {
          await addCapabilityInvocation(vmId);
        }
        for (final vmId in doc.capabilityDelegation
            .map((v) => '#${v.id.split('#').last}')) {
          await addCapabilityDelegation(vmId);
        }
      }

      return doc;
    }

    // For did:peer:2, build the document from state to preserve vmIds.
    final relationships = {
      VerificationRelationship.authentication: authentication.toList(),
      VerificationRelationship.keyAgreement: keyAgreement.toList(),
      VerificationRelationship.assertionMethod: assertionMethod.toList(),
      VerificationRelationship.capabilityInvocation:
          capabilityInvocation.toList(),
      VerificationRelationship.capabilityDelegation:
          capabilityDelegation.toList(),
    };

    return DidPeer.generateDocument(
      did: did,
      verificationMethodIds: uniqueVmIds,
      publicKeys: verificationMethodsPubKeys,
      relationships: relationships,
      serviceEndpoints: service.toList(),
    );
  }

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey) async {
    // For did:peer, verification method IDs are numbered sequentially
    // based on their order in the verificationMethod array
    final verificationMethods = await store.verificationMethodIds;

    // Verification method IDs are 1-indexed
    return '#key-${verificationMethods.length + 1}';
  }
}
