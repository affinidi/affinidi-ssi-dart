import '../did_document/service_endpoint.dart';
import 'did_key_mapping_store.dart';
import 'did_document_reference_store.dart';

/// Default implementation of [DidKeyMappingStore] and [DidDocumentReferenceStore] using in-memory maps.
///
/// This implementation provides a simple map-based storage for DID key mappings and document references.
/// For production applications that require persistence, consider implementing
/// custom stores backed by a database or file system.
class InMemoryDidKeyMappingStore implements DidKeyMappingStore {
  final Map<String, String> _keyMapping = {};

  @override
  Future<void> setMapping(
      String verificationMethodId, String walletKeyId) async {
    _keyMapping[verificationMethodId] = walletKeyId;
  }

  @override
  Future<String?> getWalletKeyId(String verificationMethodId) async {
    return _keyMapping[verificationMethodId];
  }

  @override
  Future<void> removeMapping(String verificationMethodId) async {
    _keyMapping.remove(verificationMethodId);
  }

  @override
  Future<void> clearAll() async {
    _keyMapping.clear();
  }

  @override
  Future<List<String>> get verificationMethodIds async =>
      _keyMapping.keys.toList();
}

class InMemoryDidDocumentReferenceStore implements DidDocumentReferenceStore {
  final List<String> _authentication = [];
  final List<String> _keyAgreement = [];
  final List<String> _capabilityInvocation = [];
  final List<String> _capabilityDelegation = [];
  final List<String> _assertionMethod = [];
  final List<ServiceEndpoint> _serviceEndpoints = [];

  @override
  Future<List<String>> get authentication async => _authentication;

  @override
  Future<List<String>> get keyAgreement async => _keyAgreement;

  @override
  Future<List<String>> get capabilityInvocation async => _capabilityInvocation;

  @override
  Future<List<String>> get capabilityDelegation async => _capabilityDelegation;

  @override
  Future<List<String>> get assertionMethod async => _assertionMethod;

  @override
  Future<List<ServiceEndpoint>> get serviceEndpoints async => _serviceEndpoints;

  @override
  Future<void> addAuthentication(String verificationMethodId) async {
    if (!_authentication.contains(verificationMethodId)) {
      _authentication.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeAuthentication(String verificationMethodId) async {
    _authentication.remove(verificationMethodId);
  }

  @override
  Future<void> addKeyAgreement(String verificationMethodId) async {
    if (!_keyAgreement.contains(verificationMethodId)) {
      _keyAgreement.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeKeyAgreement(String verificationMethodId) async {
    _keyAgreement.remove(verificationMethodId);
  }

  @override
  Future<void> addCapabilityInvocation(String verificationMethodId) async {
    if (!_capabilityInvocation.contains(verificationMethodId)) {
      _capabilityInvocation.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeCapabilityInvocation(String verificationMethodId) async {
    _capabilityInvocation.remove(verificationMethodId);
  }

  @override
  Future<void> addCapabilityDelegation(String verificationMethodId) async {
    if (!_capabilityDelegation.contains(verificationMethodId)) {
      _capabilityDelegation.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeCapabilityDelegation(String verificationMethodId) async {
    _capabilityDelegation.remove(verificationMethodId);
  }

  @override
  Future<void> addAssertionMethod(String verificationMethodId) async {
    if (!_assertionMethod.contains(verificationMethodId)) {
      _assertionMethod.add(verificationMethodId);
    }
  }

  @override
  Future<void> removeAssertionMethod(String verificationMethodId) async {
    _assertionMethod.remove(verificationMethodId);
  }

  @override
  Future<void> addServiceEndpoint(ServiceEndpoint endpoint) async {
    if (!_serviceEndpoints.any((se) => se.id == endpoint.id)) {
      _serviceEndpoints.add(endpoint);
    }
  }

  @override
  Future<void> removeServiceEndpoint(String id) async {
    _serviceEndpoints.removeWhere((se) => se.id == id);
  }

  @override
  Future<void> clearVerificationMethodReferences() async {
    _authentication.clear();
    _keyAgreement.clear();
    _capabilityInvocation.clear();
    _capabilityDelegation.clear();
    _assertionMethod.clear();
  }

  @override
  Future<void> clearServiceEndpoints() async {
    _serviceEndpoints.clear();
  }
}
