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
    // ── Empty relationships: one unattached VM ──
    if (relationships.isEmpty) {
      final vmId = await buildVerificationMethodId(publicKey);
      await store.setMapping(vmId, walletKeyId);
      return AddVerificationMethodResult(
        verificationMethodId: vmId,
        relationships: const {},
      );
    }

    final createdRelationships = <VerificationRelationship, String>{};

    // Skip primary VM only when sole relationship is keyAgreement on ed25519.
    final needsPrimaryVm = !(relationships.length == 1 &&
        relationships.first == VerificationRelationship.keyAgreement &&
        publicKey.type == KeyType.ed25519);

    // Build PRIMARY VM id once.
    String? primaryVmId;
    if (needsPrimaryVm) {
      primaryVmId = await buildVerificationMethodId(publicKey);
      await addVerificationMethodFromPublicKey(
        publicKey,
        verificationMethodId: primaryVmId,
      );
    }

    // Build DERIVED X25519 VM lazily.
    String? derivedVmId;

    // Fixed processing order — significant for did:peer:2 DID string generation.
    const processingOrder = [
      VerificationRelationship.authentication,
      VerificationRelationship.keyAgreement,
      VerificationRelationship.capabilityInvocation,
      VerificationRelationship.capabilityDelegation,
      VerificationRelationship.assertionMethod,
    ];

    for (final relationship
        in processingOrder.where((r) => relationships.contains(r))) {
      if (relationship == VerificationRelationship.keyAgreement &&
          publicKey.type == KeyType.ed25519) {
        if (derivedVmId == null) {
          final x25519Bytes = ed25519PublicToX25519Public(publicKey.bytes);
          final x25519Key =
              PublicKey(publicKey.id, x25519Bytes, KeyType.x25519);
          derivedVmId = await buildVerificationMethodId(x25519Key);
          await addVerificationMethodFromPublicKey(
            x25519Key,
            verificationMethodId: derivedVmId,
          );
        }
        await addKeyAgreement(derivedVmId);
        createdRelationships[relationship] = derivedVmId;
      } else {
        switch (relationship) {
          case VerificationRelationship.authentication:
            await addAuthentication(primaryVmId!);
          case VerificationRelationship.assertionMethod:
            await addAssertionMethod(primaryVmId!);
          case VerificationRelationship.capabilityInvocation:
            await addCapabilityInvocation(primaryVmId!);
          case VerificationRelationship.capabilityDelegation:
            await addCapabilityDelegation(primaryVmId!);
          case VerificationRelationship.keyAgreement:
            await addKeyAgreement(primaryVmId!);
        }
        createdRelationships[relationship] = primaryVmId;
      }
    }

    // At least one VM must have been created: either the primary or the derived.
    assert(primaryVmId != null || derivedVmId != null);

    return AddVerificationMethodResult(
      verificationMethodId: primaryVmId ?? derivedVmId!,
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

    // Create a list of public keys for each unique verification method,
    // converting Ed25519 to X25519 for keyAgreement VMs.
    //
    // NOTE: `wallet.getPublicKey()` always returns the **original** key type
    // stored in the wallet (e.g. ed25519), even for VMs that were created with
    // a derived X25519 public key in `internalAddVerificationMethod`. For
    // derived keyAgreement VMs this means the conversion below re-derives the
    // X25519 key — the result is identical because `ed25519PublicToX25519Public`
    // is a deterministic pure function. This is intentional and ensures the DID
    // document always contains the correct X25519 multibase encoding.
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
      return DidPeer.resolve(did);
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
