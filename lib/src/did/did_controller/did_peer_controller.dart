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
  final List<PublicKey> _authenticationKeys = [];
  final List<PublicKey> _keyAgreementKeys = [];
  final List<PublicKey> _allKeysInOrder = [];
  ServiceEndpointValue? _serviceEndpoint;

  /// Creates a new DID Peer controller instance.
  ///
  /// [keyMapping] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidPeerController({
    required super.keyMapping,
    required super.wallet,
  });

  /// Sets the service endpoint for the DID document.
  void setServiceEndpoint(ServiceEndpointValue? endpoint) {
    _serviceEndpoint = endpoint;
  }

  DidDocument _createDidDocumentFromState() {
    if (_authenticationKeys.isEmpty && _keyAgreementKeys.isEmpty) {
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

  /// Creates a DID document with specific keys and service endpoint.
  ///
  /// [authenticationKeys] - Keys for authentication purposes.
  /// [keyAgreementKeys] - Keys for key agreement purposes.
  /// [serviceEndpoint] - Optional service endpoint.
  ///
  /// Returns the created DID document.
  DidDocument createDidDocumentWithKeys(
    List<PublicKey> authenticationKeys,
    List<PublicKey> keyAgreementKeys, {
    ServiceEndpointValue? serviceEndpoint,
  }) {
    _authenticationKeys.clear();
    _authenticationKeys.addAll(authenticationKeys);
    _keyAgreementKeys.clear();
    _keyAgreementKeys.addAll(keyAgreementKeys);
    _serviceEndpoint = serviceEndpoint;

    _allKeysInOrder.clear();
    _allKeysInOrder.addAll(authenticationKeys);
    for (final key in keyAgreementKeys) {
      if (!_allKeysInOrder.contains(key)) {
        _allKeysInOrder.add(key);
      }
    }

    return _createDidDocumentFromState();
  }

  @override
  void addAuthenticationKey(PublicKey publicKey) {
    if (!_authenticationKeys.contains(publicKey)) {
      _authenticationKeys.add(publicKey);
    }
    if (!_allKeysInOrder.contains(publicKey)) {
      _allKeysInOrder.add(publicKey);
    }
  }

  @override
  void addKeyAgreementKey(PublicKey publicKey) {
    if (!_keyAgreementKeys.contains(publicKey)) {
      _keyAgreementKeys.add(publicKey);
    }
    if (!_allKeysInOrder.contains(publicKey)) {
      _allKeysInOrder.add(publicKey);
    }
  }

  @override
  void addCapabilityInvocationKey(PublicKey publicKey) {
    if (!_authenticationKeys.contains(publicKey)) {
      _authenticationKeys.add(publicKey);
    }
    if (!_allKeysInOrder.contains(publicKey)) {
      _allKeysInOrder.add(publicKey);
    }
  }

  @override
  void addCapabilityDelegationKey(PublicKey publicKey) {
    if (!_authenticationKeys.contains(publicKey)) {
      _authenticationKeys.add(publicKey);
    }
    if (!_allKeysInOrder.contains(publicKey)) {
      _allKeysInOrder.add(publicKey);
    }
  }

  @override
  void addAssertionMethodKey(PublicKey publicKey) {
    if (!_authenticationKeys.contains(publicKey)) {
      _authenticationKeys.add(publicKey);
    }
    if (!_allKeysInOrder.contains(publicKey)) {
      _allKeysInOrder.add(publicKey);
    }
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
