import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../../types.dart';
import '../../utility.dart';
import '../did_document/did_document.dart';
import '../did_web.dart';
import 'did_manager.dart';
import 'verification_relationship.dart';

class DidWebManager extends DidManager {
  final Uri domain;

  DidWebManager({required super.store, required super.wallet, required this.domain,});

  String get did => DidWeb.getDid(domain);

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey) async {
    // For did:web, use wallet key ID as the fragment for deterministic
    // and human-readable verification method IDs.
    // Format: did:web:example.com#<walletKeyId>
    final verificationMethods = await store.verificationMethodIds;
    final keyIndex = verificationMethods.length + 1;
    return '$did#key-$keyIndex';
  }

  @override
  Future<DidDocument> getDidDocument() async {
    // Get all verification method IDs in their creation order.
    final uniqueVmIds = await store.verificationMethodIds;

    if (uniqueVmIds.isEmpty) {
      throw SsiException(
        message:
        'At least one key must be added before creating did:web document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Build public keys list. Converting Ed25519 to X25519 for keyAgreement VMs
    final verificationMethodPublicKeys = <PublicKey>[];
    for (final vmId in uniqueVmIds) {
      final walletKeyId = await getWalletKeyId(vmId);
      if (walletKeyId == null) {
        throw SsiException(
          message: 'Could not find wallet key for $vmId',
          code: SsiExceptionType.keyNotFound.code,
        );
      }

      var publicKey = await wallet.getPublicKey(walletKeyId);
      if (keyAgreement.contains(vmId) && publicKey.type == KeyType.ed25519) {
        final x25519PublicKeyBytes =
        ed25519PublicToX25519Public(publicKey.bytes);
        publicKey =
            PublicKey(publicKey.id, x25519PublicKeyBytes, KeyType.x25519);
      }
      verificationMethodPublicKeys.add(publicKey);
    }

    // Build relationships map using verification method IDs
    final relationships = <VerificationRelationship, List<String>>{
      VerificationRelationship.authentication: authentication.toList(),
      VerificationRelationship.keyAgreement: keyAgreement.toList(),
      VerificationRelationship.assertionMethod: assertionMethod.toList(),
      VerificationRelationship.capabilityInvocation:
      capabilityInvocation.toList(),
      VerificationRelationship.capabilityDelegation:
      capabilityDelegation.toList(),
    };

    return DidWeb.generateDocument(
      did: did,
      verificationMethodIds: uniqueVmIds,
      publicKeys: verificationMethodPublicKeys,
      relationships: relationships,
      serviceEndpoints: service.toList(),
    );
  }
}