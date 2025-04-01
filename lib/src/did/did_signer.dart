import 'dart:typed_data';

import '../../affinidi_ssi.dart';
import 'did_document.dart';

class DidSigner {
  final KeyPair _keyPair;
  final SignatureScheme signatureScheme;
  final DidDocument _didDocument;
  final String didKeyId;

  // TODO validations, eg. keyId in doc, signature scheme supported, etc.
  DidSigner({
    required DidDocument didDocument,
    required this.didKeyId,
    required KeyPair keyPair,
    required this.signatureScheme,
  })  : _keyPair = keyPair,
        _didDocument = didDocument;

  String get did => _didDocument.id;

  Future<Uint8List> get publicKey => _keyPair.getPublicKey();

  Future<KeyType> get keyType => _keyPair.getKeyType();

  /// The identifier of the key inside the DID document
  String get keyId => didKeyId;

  Future<Uint8List> sign(Uint8List data) => _keyPair.sign(
        data,
        signatureScheme: signatureScheme,
      );
}
