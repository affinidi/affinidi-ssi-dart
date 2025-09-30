import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../key_pair/public_key.dart';
import '../did_document/did_document.dart';
import '../did_cheqd.dart';
import 'did_manager.dart';

/// DID Manager implementation for the did:cheqd method.
///
/// This manager handles DID documents that use the did:cheqd method,
/// which supports multiple keys with separate authentication and
/// key agreement purposes, as well as service endpoints.
class DidCheqdManager extends DidManager {
  /// Creates a new DID Cheqd manager instance.
  ///
  /// [store] - The key mapping store to use for managing key relationships.
  /// [wallet] - The wallet to use for key operations.
  DidCheqdManager({
    required super.store,
    required super.wallet,
  });

  /// Registers a new did:cheqd and stores the generated DID identifier.
  ///
  /// This method should be called after adding verification methods to register
  /// the DID on the Cheqd network and store the generated DID identifier.
  /// Uses the keys from the wallet that was passed to the manager.
  ///
  /// [keyId] - The ID of the key in the wallet to use for registration.
  /// [network] - The network to register on ('testnet' or 'mainnet'). Defaults to 'testnet'.
  /// [registrarUrl] - Optional custom registrar URL.
  ///
  /// Returns the registered DID identifier.
  ///
  /// Throws [SsiException] if registration fails.
  Future<String> registerDid(
    String keyId, {
    String network = 'testnet',
    String? registrarUrl,
  }) async {
    try {
      final did = await DidCheqd.registerWithWallet(
        wallet,
        keyId,
        network: network,
        registrarUrl: registrarUrl,
      );
      await store.setDid(did);
      return did;
    } catch (e) {
      throw SsiException(
        message: 'Failed to register did:cheqd: $e',
        code: SsiExceptionType.invalidDidCheqd.code,
      );
    }
  }

  @override
  Future<DidDocument> getDidDocument() async {
    final did = await store.did;

    if (did == null) {
      throw SsiException(
        message: 'Did not find did before creating did:cheqd document',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    return DidCheqd.resolve(did);
  }

  @override
  Future<String> buildVerificationMethodId(PublicKey publicKey) async {
    // For did:cheqd, verification method IDs are numbered sequentially
    // based on their order in the verificationMethod array
    final verificationMethods = await store.verificationMethodIds;

    // Verification method IDs are 1-indexed
    return '#key-${verificationMethods.length + 1}';
  }
}
