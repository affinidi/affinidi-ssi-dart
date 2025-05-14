import 'dart:typed_data';

import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import 'did_document/index.dart';

/// A signer that uses a key pair associated with a DID document to sign data.
class DidSigner {
  /// The wallet used for signing.
  final KeyPair _keyPair;

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
