import 'dart:typed_data';

import '../key_pair/key_pair.dart';
import '../types.dart';

/// A signer that uses a key pair associated with a DID document to sign data.
class DidSigner {
  /// The wallet used for signing.
  final KeyPair _keyPair;

  /// The signature scheme to use for signing.
  final SignatureScheme signatureScheme;

  /// The DID document containing the key information.
  final String _did;

  /// The identifier of the key inside the DID document.
  final String _didKeyId;

  /// Creates a new [DidSigner] instance.
  ///
  /// [did] - The DID for which this keyPair is being used.
  /// [didKeyId] - The identifier of the key inside the DID document.
  /// [keyPair] - The key pair to use for signing.
  /// [signatureScheme] - The signature scheme to use for signing.
  // TODO(FTL-20741) validations, eg. keyId & keyPair belongs to did, signature scheme supported, etc.
  DidSigner({
    required String did,
    required String didKeyId,
    required KeyPair keyPair,
    required this.signatureScheme,
  })  : _didKeyId = didKeyId,
        _keyPair = keyPair,
        _did = did;

  /// Returns the DID identifier from the DID document.
  String get did => _did;

  /// The identifier of the key inside the DID document
  String get keyId => _didKeyId;

  /// Signs the provided data using the key pair and signature scheme.
  Future<Uint8List> sign(Uint8List data) => _keyPair.sign(
        data,
        signatureScheme: signatureScheme,
      );
}
