/// A store for managing mappings between DID key identifiers and wallet key identifiers.
///
/// This class maintains the relationship between two different identifier systems:
/// - **DID Key ID (verification method ID)**: The identifier used in DID documents
///   (e.g., "did:key:z6Mk...#z6Mk..." or "did:peer:2.Ez...#key-1")
/// - **Wallet Key ID**: The internal identifier used by the wallet/KeyPair
///   (e.g., "key-1234567890" or a JWT thumbprint)
///
/// This mapping is necessary because the same cryptographic key has different
/// identifiers in different contexts.
abstract class DiDControllerStore {
  /// Sets a mapping between a DID key identifier and a wallet key identifier.
  ///
  /// [didKeyId] - The verification method ID from the DID document
  /// [walletKeyId] - The internal key ID used by the wallet/KeyPair
  void setMapping(String didKeyId, String walletKeyId);

  /// Gets the wallet key identifier for a given DID key identifier.
  String? getWalletKeyId(String didKeyId);

  /// Removes the mapping for a given DID key identifier.
  void removeMapping(String didKeyId);

  /// Clears all mappings.
  void clear();

  /// Gets all DID key identifiers.
  List<String> get didKeyIds;
}

/// Default implementation of [DiDControllerStore] using an in-memory map.
///
/// This implementation provides a simple map-based storage for DID key mappings.
/// For production applications that require persistence, consider implementing
/// a custom [DiDControllerStore] backed by a database or file system.
class DefaultDiDControllerStore extends DiDControllerStore {
  final Map<String, String> _keyMapping = {};

  @override
  void setMapping(String didKeyId, String walletKeyId) {
    _keyMapping[didKeyId] = walletKeyId;
  }

  @override
  String? getWalletKeyId(String didKeyId) {
    return _keyMapping[didKeyId];
  }

  @override
  void removeMapping(String didKeyId) {
    _keyMapping.remove(didKeyId);
  }

  @override
  void clear() {
    _keyMapping.clear();
  }

  @override
  List<String> get didKeyIds => _keyMapping.keys.toList();
}
