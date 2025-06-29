import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint_value.dart';
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

  Future<DidDocument> _createDidDocumentFromState() async {
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
      authPublicKeys.add(await wallet.getPublicKey(keyId));
    }

    final keyAgreementPublicKeys = <PublicKey>[];
    for (final keyId in keyAgreementKeyIds) {
      keyAgreementPublicKeys.add(await wallet.getPublicKey(keyId));
    }

    return DidPeer.generateDocument(
      authPublicKeys,
      keyAgreementPublicKeys,
      serviceEndpoint: _serviceEndpoint,
    );
  }

  /// Creates a DID document with specific key IDs and service endpoint.
  ///
  /// [authenticationKeyIds] - Key IDs for authentication purposes.
  /// [keyAgreementKeyIds] - Key IDs for key agreement purposes.
  /// [serviceEndpoint] - Optional service endpoint.
  ///
  /// Returns the created DID document.
  Future<DidDocument> createDidDocumentWithKeys(
    List<String> authenticationKeyIds,
    List<String> keyAgreementKeyIds, {
    ServiceEndpointValue? serviceEndpoint,
  }) async {
    // Clear all existing keys
    keysByPurpose.clear();

    // Add authentication keys
    for (final keyId in authenticationKeyIds) {
      addAuthenticationKey(keyId);
    }

    // Add key agreement keys
    for (final keyId in keyAgreementKeyIds) {
      addKeyAgreementKey(keyId);
    }

    _serviceEndpoint = serviceEndpoint;

    return await _createDidDocumentFromState();
  }

  // DidPeerController now uses the base class implementation for all addXXX methods

  @override
  Future<DidDocument> createOrUpdateDocument() async {
    return await _createDidDocumentFromState();
  }

  @override
  Future<String> buildVerificationMethodId(String keyId) async {
    // For did:peer, verification method IDs are numbered sequentially
    // based on their order in the verificationMethod array
    final verificationMethods = await store.verificationMethodIds;

    // Verification method IDs are 1-indexed
    return '#key-${verificationMethods.length + 1}';
  }
}
