import '../did_document/service_endpoint.dart';

/// Interface for managing verification method references and service endpoints.
abstract class DidDocumentReferenceStore {
  Future<List<String>> get authentication;
  Future<List<String>> get keyAgreement;
  Future<List<String>> get capabilityInvocation;
  Future<List<String>> get capabilityDelegation;
  Future<List<String>> get assertionMethod;
  Future<List<ServiceEndpoint>> get serviceEndpoints;

  Future<void> addAuthentication(String verificationMethodId);
  Future<void> removeAuthentication(String verificationMethodId);
  Future<void> addKeyAgreement(String verificationMethodId);
  Future<void> removeKeyAgreement(String verificationMethodId);
  Future<void> addCapabilityInvocation(String verificationMethodId);
  Future<void> removeCapabilityInvocation(String verificationMethodId);
  Future<void> addCapabilityDelegation(String verificationMethodId);
  Future<void> removeCapabilityDelegation(String verificationMethodId);
  Future<void> addAssertionMethod(String verificationMethodId);
  Future<void> removeAssertionMethod(String verificationMethodId);
  Future<void> addServiceEndpoint(ServiceEndpoint endpoint);
  Future<void> removeServiceEndpoint(String id);
  Future<void> clearVerificationMethodReferences();
  Future<void> clearServiceEndpoints();
}
