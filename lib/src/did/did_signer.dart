import 'dart:typed_data';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
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
  ///
  /// Throws [SsiException] if parameters are invalid or incompatible.
  DidSigner({
    required String did,
    required String didKeyId,
    required KeyPair keyPair,
    required this.signatureScheme,
  })  : _didKeyId = didKeyId,
        _keyPair = keyPair,
        _did = did {
    _validateParameters(did, didKeyId, keyPair, signatureScheme);
  }

  /// Returns the DID identifier from the DID document.
  String get did => _did;

  /// The identifier of the key inside the DID document
  String get keyId => _didKeyId;

  /// Signs the provided data using the key pair and signature scheme.
  Future<Uint8List> sign(Uint8List data) => _keyPair.sign(
        data,
        signatureScheme: signatureScheme,
      );

  /// Returns the full DID key identifier by combining the `did` and `keyId` if `keyId` starts with '#'.
  /// If `keyId` does not start with '#', returns `keyId` as is.
  ///
  /// Example:
  /// - If `did` is 'did:example:123' and `keyId` is '#key-1', returns 'did:example:123#key-1'.
  /// - If `keyId` is 'key-1', returns 'key-1'.
  String get didKeyId => keyId.startsWith('#') ? '$did$keyId' : keyId;

  /// Validates constructor parameters to ensure consistency and security.
  static void _validateParameters(
    String did,
    String didKeyId,
    KeyPair keyPair,
    SignatureScheme signatureScheme,
  ) {
    if (did.isEmpty) {
      throw SsiException(
        message: 'DID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }

    if (!did.startsWith('did:')) {
      throw SsiException(
        message: 'Invalid DID format: must start with "did:"',
        code: SsiExceptionType.other.code,
      );
    }

    if (didKeyId.isEmpty) {
      throw SsiException(
        message: 'DID key ID cannot be empty',
        code: SsiExceptionType.other.code,
      );
    }

    if (!keyPair.supportedSignatureSchemes.contains(signatureScheme)) {
      throw SsiException(
        message:
            'Signature scheme ${signatureScheme.name} is not supported by this key pair. '
            'Supported schemes: [${keyPair.supportedSignatureSchemes.map((s) => s.name).join(', ')}]',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
  }
}
