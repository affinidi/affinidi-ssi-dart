import 'dart:typed_data';

import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import '../wallet/persistent_wallet.dart';
import '../wallet/wallet.dart';
import 'did_document/index.dart';
import 'universal_did_resolver.dart';

/// A signer that uses a key pair associated with a DID document to sign data.
class DidSigner {
  /// The wallet used for signing.
  final KeyPair _keyPair;

  /// The signature scheme to use for signing.
  final SignatureScheme signatureScheme;

  /// The DID document containing the key information.
  final DidDocument _didDocument;

  /// The identifier of the key inside the DID document (verification method ID).
  ///
  /// This is the DID URL that identifies a specific verification method
  /// within the DID document (e.g., "did:key:z6Mk...#z6Mk...").
  /// It is NOT the same as the wallet key ID used by KeyPair.
  ///
  /// The relationship between this ID and the wallet key ID is managed
  /// by the DidController through its keyMapping store.
  final String didKeyId;

  /// Creates a new [DidSigner] instance.
  ///
  /// [didDocument] - The DID document containing the key information.
  /// [didKeyId] - The identifier of the key inside the DID document.
  /// [keyPair] - The key pair to use for signing.
  /// [signatureScheme] - The signature scheme to use for signing.
  // TODO(FTL-20741) validations, eg. keyId in doc, signature scheme supported, etc.
  DidSigner({
    required DidDocument didDocument,
    required this.didKeyId,
    required KeyPair keyPair,
    required this.signatureScheme,
  })  : _keyPair = keyPair,
        _didDocument = didDocument;

  /// Creates a new [DidSigner] instance from a wallet and a DID.
  ///
  /// This method resolves the DID document, retrieves the key pair from the
  /// wallet, and creates a [DidSigner] configured for signing.
  ///
  /// [wallet] - The wallet containing the key pair.
  /// [did] - The DID string for which to create the signer.
  /// [keyId] - The identifier of the key within the wallet.
  /// [signatureScheme] - Optional signature scheme to use for signing.
  ///
  /// Returns a [Future] that completes with the created [DidSigner] instance.
  ///
  /// Throws {@link SsiException} if the DID document cannot be resolved or the key is not found.
  static Future<DidSigner> from(
    Wallet wallet,
    String did,
    String keyId, {
    SignatureScheme? signatureScheme,
  }) async {
    final didDocument = await UniversalDIDResolver.resolve(did);

    KeyPair keyPair;
    if (wallet is PersistentWallet) {
      keyPair = await wallet.getKeyPair(keyId);
    } else {
      keyPair = await wallet.generateKey(keyId: keyId);
    }

    final effectiveSignatureScheme =
        signatureScheme ?? keyPair.defaultSignatureScheme;

    // TODO: shouldnt this use the first *authentication* verification method?
    final verificationMethodId = didDocument.verificationMethod.isNotEmpty
        ? didDocument.verificationMethod.first.id
        : '$did#$keyId';

    return DidSigner(
      didDocument: didDocument,
      didKeyId: verificationMethodId,
      keyPair: keyPair,
      signatureScheme: effectiveSignatureScheme,
    );
  }

  /// Returns the DID identifier from the DID document.
  String get did => _didDocument.id;

  /// Returns the public key from the key pair.
  PublicKey get publicKey => _keyPair.publicKey;

  /// The identifier of the key inside the DID document
  String get keyId => didKeyId;

  /// Signs the provided data using the key pair and signature scheme.
  Future<Uint8List> sign(Uint8List data) => _keyPair.sign(
        data,
        signatureScheme: signatureScheme,
      );
}
