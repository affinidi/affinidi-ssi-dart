import 'did_controller_store.dart';

/// Default implementation of [DidStore] using an in-memory map.
///
/// This implementation provides a simple map-based storage for DID key mappings.
/// For production applications that require persistence, consider implementing
/// a custom [DidStore] backed by a database or file system.
class InMemoryDidStore extends DidStore {
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
