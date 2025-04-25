import '../key_pair/key_pair.dart';
import '../types.dart';
import 'wallet.dart';

/// An interface for wallets that support hierarchical deterministic key generation
/// using derivation paths (e.g., BIP32, SLIP-0010).
abstract interface class DeterministicWallet implements Wallet {
  /// Generates a new key pair using a derivation path and stores it.
  ///
  /// Returns a [Future] that completes with the [KeyPair] of the generated key.
  /// If a [keyId] is provided and already exists, it might return the existing key
  /// or throw an error, depending on the implementation and whether the existing
  /// key matches the requested parameters.
  ///
  /// [keyId] - An optional identifier for the key. If not provided, one might be generated.
  /// [keyType] - The type of key to generate (e.g., secp256k1, ed25519). Defaults vary by implementation.
  /// [derivationPath] - The hierarchical derivation path (e.g., "m/44'/0'/0'/0/0"). This is required.
  Future<KeyPair> deriveKey({
    String? keyId,
    KeyType? keyType,
    required String derivationPath,
  });
}
