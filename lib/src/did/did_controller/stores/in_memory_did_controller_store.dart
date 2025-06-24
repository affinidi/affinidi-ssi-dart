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
abstract class DiDControllerStore {
  /// Sets a mapping between a DID key identifier and a wallet key identifier.
  ///
  /// [verificationMethodId] - The verification method ID from the DID document
  /// [walletKeyId] - The internal key ID used by the wallet/KeyPair
  void setMapping(String verificationMethodId, String walletKeyId);

  /// Gets the wallet key identifier for a given verification method identifier.
  String? getWalletKeyId(String verificationMethodId);

  /// Removes the mapping for a given verification method identifier.
  void removeMapping(String verificationMethodId);

  /// Clears all mappings.
  void clear();

  /// Gets all DID key identifiers.
  List<String> get verificationMethodIds;
}

/// Default implementation of [DiDControllerStore] using an in-memory map.
///
/// This implementation provides a simple map-based storage for DID key mappings.
/// For production applications that require persistence, consider implementing
/// a custom [DiDControllerStore] backed by a database or file system.
class DefaultDiDControllerStore extends DiDControllerStore {
  final Map<String, String> _keyMapping = {};

  @override
  void setMapping(String verificationMethodId, String walletKeyId) {
    _keyMapping[verificationMethodId] = walletKeyId;
  }

  @override
  String? getWalletKeyId(String verificationMethodId) {
    return _keyMapping[verificationMethodId];
  }

  @override
  void removeMapping(String verificationMethodId) {
    _keyMapping.remove(verificationMethodId);
  }

  @override
  void clear() {
    _keyMapping.clear();
  }

  @override
  List<String> get verificationMethodIds => _keyMapping.keys.toList();
}
