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
}
