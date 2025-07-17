/// Interface for mapping between verification method IDs and wallet key IDs.
abstract class DidKeyMappingStore {
  Future<void> setMapping(String verificationMethodId, String walletKeyId);
  Future<String?> getWalletKeyId(String verificationMethodId);
  Future<void> removeMapping(String verificationMethodId);
  Future<void> clearAll();
  Future<List<String>> get verificationMethodIds;
}
