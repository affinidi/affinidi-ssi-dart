import 'dart:typed_data';

import '../key_pair/public_key.dart';
import '../types.dart';
import '../wallet/wallet.dart';
import 'did_document.dart';

/// A signer that uses a key pair associated with a DID document to sign data.
class DidSigner {
  /// The wallet used for signing.
  final Wallet _wallet;
  final String _walletKeyId;

  /// The signature scheme to use for signing.
  final SignatureScheme signatureScheme;

  /// The DID document containing the key information.
  final DidDocument _didDocument;

  /// The identifier of the key inside the DID document.
  final String didKeyId;

  /// Creates a new [DidSigner] instance.
  ///
  /// [didDocument] - The DID document containing the key information.
  /// [didKeyId] - The identifier of the key inside the DID document.
  /// [wallet] - The wallet to use for signing.
  /// [walletKeyId] - The id of the key in the wallet to use for signing.
  /// [signatureScheme] - The signature scheme to use for signing.
  // TODO(FTL-20741) validations, eg. keyId in doc, signature scheme supported, etc.
  DidSigner({
    required DidDocument didDocument,
    required this.didKeyId,
    required Wallet wallet,
    required String walletKeyId,
    required this.signatureScheme,
  })  : _wallet = wallet,
        _walletKeyId = walletKeyId,
        _didDocument = didDocument;

  String get did => _didDocument.id;

  Future<PublicKey> get publicKey => _wallet.getPublicKey(_walletKeyId);

  /// The identifier of the key inside the DID document
  String get keyId => didKeyId;

  Future<Uint8List> sign(Uint8List data) => _wallet.sign(
        data,
        keyId: _walletKeyId,
        signatureScheme: signatureScheme,
      );
}
