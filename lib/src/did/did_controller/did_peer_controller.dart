import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../did_document/did_document.dart';
import '../did_peer.dart';
import 'did_controller.dart';

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
  Future<DidDocument> createOrUpdateDocument() async {
    if (authentication.isEmpty && keyAgreement.isEmpty) {
      throw SsiException(
        message:
            'At least one key must be added before creating did:peer document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Convert key IDs to PublicKey objects
    final authPublicKeys = <PublicKey>[];
    for (final verificationMethodId in authentication) {
      final walletKeyId = await getWalletKeyId(verificationMethodId);
      if (walletKeyId != null) {
        authPublicKeys.add(await wallet.getPublicKey(walletKeyId));
      }
    }

    final keyAgreementPublicKeys = <PublicKey>[];
    for (final verificationMethodId in keyAgreement) {
      final walletKeyId = await getWalletKeyId(verificationMethodId);
      if (walletKeyId != null) {
        keyAgreementPublicKeys.add(await wallet.getPublicKey(walletKeyId));
      }
    }

    return DidPeer.generateDocument(
      authPublicKeys,
      keyAgreementPublicKeys,
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
