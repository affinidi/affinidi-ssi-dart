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
  /// The preferred numalgo for DID generation.
  ///
  /// - [DidPeerType.peer2] (default): always produces `did:peer:2`.
  /// - [DidPeerType.peer0]: produces `did:peer:0` when possible
  ///   (single VM, no services); falls back to `did:peer:2` otherwise.
  final DidPeerType preferredNumalgo;

  /// Creates a new DID Peer manager instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  /// [preferredNumalgo] - The preferred numalgo (default: [DidPeerType.peer2]).
  DidPeerManager({
    required super.store,
    required super.wallet,
    this.preferredNumalgo = DidPeerType.peer2,
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

    // For did:peer:0, collapse an Ed25519 + derived X25519 pair back to
    // just the Ed25519 source key. The resolution logic (_buildEDDoc) will
    // re-derive the X25519 keyAgreement automatically.
    var vmIdsForDid = uniqueVmIds;
    var pubKeysForDid = verificationMethodsPubKeys;

    if (preferredNumalgo == DidPeerType.peer0 &&
        service.isEmpty &&
        _isEd25519WithDerivedX25519(uniqueVmIds, verificationMethodsPubKeys)) {
      // Find the Ed25519 source key (not the derived X25519).
      final ed25519Index = verificationMethodsPubKeys
          .indexWhere((k) => k.type == KeyType.ed25519);
      // Retrieve the original Ed25519 public key from the wallet.
      final walletKeyId = await getWalletKeyId(uniqueVmIds[ed25519Index]);
      final ed25519Key = await wallet.getPublicKey(walletKeyId!);

      vmIdsForDid = [uniqueVmIds[ed25519Index]];
      pubKeysForDid = [ed25519Key];
    }

    // Create a map from verification method ID to its index in the list.
    final vmIdToIndex = <String, int>{
      for (var i = 0; i < vmIdsForDid.length; i++) vmIdsForDid[i]: i
    };

    // For each relationship, create a list of key indices.
    // VMs not present in vmIdsForDid (e.g. collapsed derived X25519) are
    // skipped — the resolution logic will reconstruct them.
    List<int> getIndexes(Iterable<String> vmIds) {
      return vmIds
          .where((vmId) => vmIdToIndex.containsKey(vmId))
          .map((vmId) => vmIdToIndex[vmId]!)
          .toList();
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
      verificationMethods: pubKeysForDid,
      relationships: relationshipIndexes,
      serviceEndpoints: service.toList(),
      preferredNumalgo: preferredNumalgo,
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

  /// Returns `true` when [vmIds]/[pubKeys] represent exactly one Ed25519
  /// source key and its derived X25519 key — the pattern produced by
  /// [internalAddVerificationMethod] for Ed25519 + keyAgreement.
  static bool _isEd25519WithDerivedX25519(
    List<String> vmIds,
    List<PublicKey> pubKeys,
  ) {
    if (pubKeys.length != 2) return false;
    final types = pubKeys.map((k) => k.type).toSet();
    return types.contains(KeyType.ed25519) && types.contains(KeyType.x25519);
  }
}
