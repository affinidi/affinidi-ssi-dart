import 'dart:typed_data';

import '../key_pair/key_pair.dart';
import '../types.dart';
import 'did_document.dart';

/// A signer that uses a key pair associated with a DID document to sign data.
class DidSigner {
  /// The key pair used for signing.
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
  // TODO validations, eg. keyId in doc, signature scheme supported, etc.
  DidSigner({
    required DidDocument didDocument,
    required this.didKeyId,
    required KeyPair keyPair,
    required this.signatureScheme,
  })  : _keyPair = keyPair,
        _didDocument = didDocument;

  String get did => _didDocument.id;

  Future<Uint8List> get publicKey => _keyPair.publicKey;

  Future<KeyType> get keyType => _keyPair.publicKeyType;

  /// The identifier of the key inside the DID document
  String get keyId => didKeyId;

  Future<Uint8List> sign(Uint8List data) => _keyPair.sign(
        data,
        signatureScheme: signatureScheme,
      );
}
