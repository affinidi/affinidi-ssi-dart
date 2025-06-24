import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../did_document/did_document.dart';
import '../did_document/service_endpoint.dart';
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

  DidDocument _createDidDocumentFromState() {
    if (authentication.isEmpty && keyAgreement.isEmpty) {
      throw SsiException(
        message: 'At least one key must be added before creating a document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    return DidPeer.generateDocument(
      _authenticationKeys,
      _keyAgreementKeys,
      serviceEndpoint: _serviceEndpoint,
    );
  }

  @override
  Future<DidDocument> createOrUpdateDocument() async {
    return _createDidDocumentFromState();
  }

  @override
  Future<String> findVerificationMethodId(PublicKey publicKey) async {
    // For did:peer, verification method IDs are numbered sequentially
    // based on their order in the verificationMethod array

    final index = _allKeysInOrder.indexOf(publicKey);
    if (index == -1) {
      throw SsiException(
        message: 'Verification method not found for public key',
        code: SsiExceptionType.keyNotFound.code,
      );
    }

    // Verification method IDs are 1-indexed
    return '#key-${index + 1}';
  }
}
