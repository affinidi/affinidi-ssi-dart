import 'dart:typed_data';

import '../key_pair/key_pair.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import 'did_document/did_document.dart';

/// A wrapper that combines a cryptographic key pair with its DID context.
///
/// This class provides a convenient way to work with keys in the context of
/// DIDs, combining the cryptographic capabilities of a [KeyPair] with the
/// DID-specific metadata like the verification method ID and DID document.
///
/// The relationship between identifiers:
/// - [walletKeyId]: The internal identifier used by the wallet/KeyPair (e.g., "key-1234567890")
/// - [verificationMethodId]: The DID URL identifying the verification method (e.g., "did:key:z6Mk...#z6Mk...")
class DidKeyPair {
  /// The underlying cryptographic key pair.
  final KeyPair keyPair;

  /// The DID verification method identifier.
  ///
  /// This is the DID URL that identifies a specific verification method
  /// within a DID document (e.g., "did:key:z6Mk...#z6Mk...").
  final String verificationMethodId;

  /// The optional DID document context.
  ///
  /// When available, provides the full DID document containing this key's
  /// verification method.
  final DidDocument? didDocument;

  /// Creates a new [DidKeyPair] instance.
  ///
  /// [keyPair] - The underlying cryptographic key pair.
  /// [verificationMethodId] - The DID verification method identifier.
  /// [didDocument] - Optional DID document containing this key's verification method.
  DidKeyPair({
    required this.keyPair,
    required this.verificationMethodId,
    this.didDocument,
  });

  /// The wallet-internal identifier for this key pair.
  ///
  /// This is the identifier used by the wallet to reference this key
  /// (e.g., "key-1234567890"), not the DID verification method ID.
  String get walletKeyId => keyPair.id;

  /// The public key associated with this key pair.
  PublicKey get publicKey => keyPair.publicKey;

  /// The DID identifier.
  ///
  /// Extracted from the DID document if available, or derived from the
  /// verification method ID by taking the portion before the fragment (#).
  String get did => didDocument?.id ?? verificationMethodId.split('#').first;

  /// Returns a list of signature schemes supported by this key pair.
  List<SignatureScheme> get supportedSignatureSchemes =>
      keyPair.supportedSignatureSchemes;

  /// Signs the provided data using the underlying key pair.
  ///
  /// [data] - The data to be signed.
  /// [signatureScheme] - Optional signature scheme to use.
  ///
  /// Returns a [Future] that completes with the signature as a [Uint8List].
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) =>
      keyPair.sign(data, signatureScheme: signatureScheme);

  /// Verifies a signature using the underlying key pair.
  ///
  /// [data] - The original data that was signed.
  /// [signature] - The signature to verify.
  /// [signatureScheme] - Optional signature scheme to use.
  ///
  /// Returns a [Future] that completes with `true` if the signature is valid.
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  }) =>
      keyPair.verify(data, signature, signatureScheme: signatureScheme);

  /// Encrypts data using the underlying key pair.
  ///
  /// [data] - The data to encrypt.
  /// [publicKey] - Optional public key for encryption.
  ///
  /// Returns a [Future] that completes with the encrypted data.
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey}) =>
      keyPair.encrypt(data, publicKey: publicKey);

  /// Decrypts data using the underlying key pair.
  ///
  /// [data] - The encrypted data to decrypt.
  /// [publicKey] - Optional public key for decryption.
  ///
  /// Returns a [Future] that completes with the decrypted data.
  Future<Uint8List> decrypt(Uint8List data, {Uint8List? publicKey}) =>
      keyPair.decrypt(data, publicKey: publicKey);
}
