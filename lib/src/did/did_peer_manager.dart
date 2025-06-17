import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import 'did_controller.dart';
import 'did_document/did_document.dart';
import 'did_document/service_endpoint_value.dart';
import 'did_document/verification_method.dart';
import 'did_peer.dart';

/// Purpose of a verification method in a DID document.
enum VerificationMethodPurpose {
  /// Used for authentication.
  authentication,

  /// Used for key agreement.
  keyAgreement,

  /// Used for both authentication and key agreement.
  both,
}

/// DID Controller implementation for the did:peer method.
///
/// This controller handles DID documents that use the did:peer method,
/// which supports multiple keys with separate authentication and
/// key agreement purposes, as well as service endpoints.
class DidPeerManager extends DidController {
  final List<PublicKey> _authenticationKeys = [];
  final List<PublicKey> _keyAgreementKeys = [];
  ServiceEndpointValue? _serviceEndpoint;
  bool _documentNeedsUpdate = true;

  /// Creates a new DID Peer controller instance.
  ///
  /// [keyMapping] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  /// [document] - An optional existing DID document to manage.
  DidPeerManager({
    required super.keyMapping,
    required super.wallet,
    super.document,
  });

  /// Sets the service endpoint for the DID document.
  void setServiceEndpoint(ServiceEndpointValue? endpoint) {
    _serviceEndpoint = endpoint;
    _documentNeedsUpdate = true;
  }

  DidDocument _createDidDocumentFromState() {
    if (_authenticationKeys.isEmpty && _keyAgreementKeys.isEmpty) {
      throw SsiException(
        message: 'At least one key must be added before creating a document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    final newDocument = DidPeer.generateDocument(
      _authenticationKeys,
      _keyAgreementKeys,
      serviceEndpoint: _serviceEndpoint,
    );
    _documentNeedsUpdate = false;
    return newDocument;
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
    _documentNeedsUpdate = true;

    final newDocument = _createDidDocumentFromState();
    setDocument(newDocument);
    return newDocument;
  }

  @override
  Future<String> createVerificationMethod(
    KeyType keyType, {
    String? keyId,
    SignatureScheme? signatureScheme,
    bool useJwtThumbprint = false,
    VerificationMethodPurpose purpose =
        VerificationMethodPurpose.authentication,
  }) async {
    final walletKeyId = keyId ??
        (useJwtThumbprint
            ? await generateJwtThumbprintKeyId(keyType)
            : generateKeyId());
    final keyPair = await wallet.generateKey(
      keyId: walletKeyId,
      keyType: keyType,
    );

    // Add key to appropriate list based on purpose
    if (purpose == VerificationMethodPurpose.keyAgreement ||
        purpose == VerificationMethodPurpose.both) {
      _keyAgreementKeys.add(keyPair.publicKey);
    }
    if (purpose == VerificationMethodPurpose.authentication ||
        purpose == VerificationMethodPurpose.both) {
      _authenticationKeys.add(keyPair.publicKey);
    }

    _documentNeedsUpdate = true;

    // Regenerate document if needed or use cached
    if (_documentNeedsUpdate || document == null) {
      final didDocument = _createDidDocumentFromState();
      setDocument(didDocument);
    }

    // Find the verification method ID for this key
    final verificationMethodId = document!.verificationMethod
        .where((vm) =>
            vm is VerificationMethodMultibase &&
            vm.publicKeyMultibase.contains(keyPair.publicKey.bytes.toString()))
        .first
        .id;

    keyMapping.setMapping(verificationMethodId, walletKeyId);

    return verificationMethodId;
  }

  @override
  Future<String> addVerificationMethod(
    KeyType keyType,
    String walletKeyId, {
    SignatureScheme? signatureScheme,
    VerificationMethodPurpose purpose =
        VerificationMethodPurpose.authentication,
  }) async {
    final publicKey = await wallet.getPublicKey(walletKeyId);

    // Add key to appropriate list based on purpose
    if (purpose == VerificationMethodPurpose.keyAgreement ||
        purpose == VerificationMethodPurpose.both) {
      _keyAgreementKeys.add(publicKey);
    }
    if (purpose == VerificationMethodPurpose.authentication ||
        purpose == VerificationMethodPurpose.both) {
      _authenticationKeys.add(publicKey);
    }

    _documentNeedsUpdate = true;

    // Regenerate document if needed or use cached
    if (_documentNeedsUpdate || document == null) {
      final didDocument = _createDidDocumentFromState();
      setDocument(didDocument);
    }

    // Find the verification method ID for this key
    final verificationMethodId = document!.verificationMethod
        .where((vm) =>
            vm is VerificationMethodMultibase &&
            vm.publicKeyMultibase.contains(publicKey.bytes.toString()))
        .first
        .id;

    keyMapping.setMapping(verificationMethodId, walletKeyId);

    return verificationMethodId;
  }
}
