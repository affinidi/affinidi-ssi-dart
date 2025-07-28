import 'dart:typed_data';
import 'package:meta/meta.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import 'public_key.dart';

/// An abstract interface for cryptographic key pairs used for signing and verifying data.
abstract class KeyPair {
  /// Wallet-internal identifier for this key pair.
  ///
  /// This is a local identifier used to reference the key within a wallet.
  /// It is NOT the same as a DID verification method ID which appears in DID
  /// documents (e.g., "did:key:z6Mk...#z6Mk...").
  ///
  /// For DID operations, a mapping between this wallet key ID and the DID
  /// verification method ID is maintained by the DidManager.
  String get id;

  /// Returns a list of [SignatureScheme]s supported by this key pair.
  List<SignatureScheme> get supportedSignatureSchemes =>
      [defaultSignatureScheme];

  /// Returns the default signature scheme that is used if none is provided.
  SignatureScheme get defaultSignatureScheme;

  /// Returns the public key as as a touple with the type and bytes.
  PublicKey get publicKey;

  ///
  @protected
  Future<Uint8List> internalSign(
      Uint8List data, SignatureScheme signatureScheme);

  /// Signs the provided data using P-256 with SHA-256 hashing (ecdsa_p256_sha256).
  ///
  /// [data] - The data to be signed.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with the signature in compact format
  /// as a [Uint8List].
  ///
  /// Throws [SsiException] if an unsupported [signatureScheme] is passed.
  @nonVirtual
  Future<Uint8List> sign(
    Uint8List data, {
    SignatureScheme? signatureScheme,
  }) {
    signatureScheme =
        _validateSignatureScheme(signatureScheme: signatureScheme);
    return internalSign(data, signatureScheme);
  }

  ///
  @protected
  Future<bool> internalVerify(
      Uint8List data, Uint8List signature, SignatureScheme signatureScheme);

  /// Verifies a signature for the given [data] using the public key and optionally a [signatureScheme].
  ///
  /// [data] - The data that was signed.
  /// [signature] - The signature to verify.
  /// [signatureScheme] - The signature scheme to use.
  ///
  /// Returns a [Future] that completes with `true` if the signature is valid, `false` otherwise.
  ///
  /// Throws [SsiException] if an unsupported [signatureScheme] is passed.
  @nonVirtual
  Future<bool> verify(
    Uint8List data,
    Uint8List signature, {
    SignatureScheme? signatureScheme,
  }) {
    signatureScheme =
        _validateSignatureScheme(signatureScheme: signatureScheme);
    return internalVerify(data, signature, signatureScheme);
  }

  /// Encrypts the provided data using the public key.
  Future<Uint8List> encrypt(Uint8List data, {Uint8List? publicKey});

  /// Decrypts the provided data using the public key.
  Future<Uint8List> decrypt(Uint8List data, {Uint8List? publicKey});

  /// Computes the Elliptic Curve Diffie-Hellman (ECDH) shared secret.
  ///
  /// [publicKey] - The public key of the other party.
  ///
  /// Returns the computed shared secret as a [Uint8List].
  Future<Uint8List> computeEcdhSecret(Uint8List publicKey);

  SignatureScheme _validateSignatureScheme({
    SignatureScheme? signatureScheme,
  }) {
    signatureScheme ??= defaultSignatureScheme;
    if (!supportedSignatureSchemes.contains(signatureScheme)) {
      throw SsiException(
        message:
            'Unsupported signature scheme. Supported schemes: [${supportedSignatureSchemes.join(',')}].',
        code: SsiExceptionType.unsupportedSignatureScheme.code,
      );
    }
    return signatureScheme;
  }
}
