/// A store for managing mappings between DID key identifiers and wallet key identifiers.
///
/// This class maintains the relationship between two different identifier systems:
/// - **Verification Method ID**: The identifier used in DID documents
///   (e.g., "did:key:z6Mk...#z6Mk..." or "did:peer:2.Ez...#key-1")
/// - **Wallet Key ID**: The internal identifier used by the wallet/KeyPair
///   (e.g., "key-1234567890" or a JWT thumbprint)
///
/// This mapping is necessary because the same cryptographic key has different
/// identifiers in different contexts.
abstract class DidStore {
  /// Sets a mapping between a DID key identifier and a wallet key identifier.
  ///
  /// [verificationMethodId] - The verification method ID from the DID document
  /// [walletKeyId] - The internal key ID used by the wallet/KeyPair
  Future<void> setMapping(String verificationMethodId, String walletKeyId);

  /// Gets the wallet key identifier for a given verification method identifier.
  Future<String?> getWalletKeyId(String verificationMethodId);

  /// Removes the mapping for a given verification method identifier.
  Future<void> removeMapping(String verificationMethodId);

  /// Clears all mappings.
  Future<void> clear();

  /// Gets all DID key identifiers.
  Future<List<String>> get verificationMethodIds;

  /// Gets all verification method references for authentication.
  Future<List<String>> get authentication;

  /// Gets all verification method references for key agreement.
  Future<List<String>> get keyAgreement;

  /// Gets all verification method references for capability invocation.
  Future<List<String>> get capabilityInvocation;

  /// Gets all verification method references for capability delegation.
  Future<List<String>> get capabilityDelegation;

  /// Gets all verification method references for assertion method.
  Future<List<String>> get assertionMethod;

  /// Adds a verification method reference to authentication.
  Future<void> addAuthentication(String verificationMethodId);

  /// Removes a verification method reference from authentication.
  Future<void> removeAuthentication(String verificationMethodId);

  /// Adds a verification method reference to key agreement.
  Future<void> addKeyAgreement(String verificationMethodId);

  /// Removes a verification method reference from key agreement.
  Future<void> removeKeyAgreement(String verificationMethodId);

  /// Adds a verification method reference to capability invocation.
  Future<void> addCapabilityInvocation(String verificationMethodId);

  /// Removes a verification method reference from capability invocation.
  Future<void> removeCapabilityInvocation(String verificationMethodId);

  /// Adds a verification method reference to capability delegation.
  Future<void> addCapabilityDelegation(String verificationMethodId);

  /// Removes a verification method reference from capability delegation.
  Future<void> removeCapabilityDelegation(String verificationMethodId);

  /// Adds a verification method reference to assertion method.
  Future<void> addAssertionMethod(String verificationMethodId);

  /// Removes a verification method reference from assertion method.
  Future<void> removeAssertionMethod(String verificationMethodId);

  /// Clears all verification method references.
  Future<void> clearVerificationMethodReferences();
}
