import 'dart:typed_data';

import '../key_pair/key_pair.dart';
import '../types.dart';
import 'did_document.dart';

class DidSigner {
  final KeyPair _keyPair;
  final SignatureScheme signatureScheme;
  final DidDocument _didDocument;
  final String didKeyId;

  // TODO(FTL-20741) validations, eg. keyId in doc, signature scheme supported, etc.
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
