import 'package:base_codecs/base_codecs.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../json_ld/context.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import '../utility.dart';
import 'did_document/index.dart';
import 'public_key_utils.dart';

/// Specifies the verification method format for Ed25519 keys in DID documents.
///
/// The DID:key specification allows for different verification method types
/// and key formats, both of which encode the same cryptographic material.
///
/// This also determines the format for the derived X25519 key agreement method.
enum Ed25519VerificationMethodFormat {
  /// Uses Ed25519VerificationKey2018 with publicKeyJwk format.
  /// Also uses X25519KeyAgreementKey2019 with publicKeyBase58 format.
  ///
  /// This is the older W3C specification (2018/2019 era).
  /// - Ed25519: JSON Web Key (JWK) format
  /// - X25519: Base58 encoded format
  /// Context: https://www.w3.org/ns/did/v1
  /// Widely supported by external DID resolvers and older systems.
  jwk2018,

  /// Uses Ed25519VerificationKey2020 with publicKeyMultibase format.
  /// Also uses X25519KeyAgreementKey2020 with publicKeyMultibase format.
  ///
  /// This is the newer W3C specification (2020 era).
  /// - Ed25519: Multibase encoded format
  /// - X25519: Multibase encoded format
  /// Context: https://w3id.org/security/suites/ed25519-2020/v1
  /// More compact and consistent representation.
  multibase2020,
}

/// Builds a DID document for Ed25519 keys.
///
/// This function creates a DID document with both verification and key agreement methods
/// by converting the Ed25519 public key to an X25519 key.
///
/// [context] - The context list for the DID document
/// [id] - The DID identifier
/// [keyPart] - The key part of the DID
/// [format] - The verification method format (defaults to multibase2020)
///
/// Returns a [DidDocument]
///
/// Throws [SsiException] if the conversion fails.
DidDocument _buildEDDoc(
  List<String> context,
  String id,
  String keyPart, {
  Ed25519VerificationMethodFormat format =
      Ed25519VerificationMethodFormat.multibase2020,
}) {
  final x25519PubKey = ed25519PublicToX25519Public(
    base58Bitcoin.decode(keyPart).sublist(2),
  );
  final x25519PubKeyMultiBase = toMultiBase(
    toMultikey(x25519PubKey, KeyType.x25519),
  );

  final verificationKeyId = '$id#z$keyPart';
  final agreementKeyId = '$id#$x25519PubKeyMultiBase';

  // Create the verification method based on the requested format
  final EmbeddedVerificationMethod verification;
  final EmbeddedVerificationMethod keyAgreement;

  switch (format) {
    case Ed25519VerificationMethodFormat.jwk2018:
      // Convert the multibase key to JWK format
      final ed25519MultiKey = toMultikey(
        base58Bitcoin.decode(keyPart).sublist(2),
        KeyType.ed25519,
      );
      final jwk = Jwk.fromJson(multiKeyToJwk(ed25519MultiKey));
      verification = VerificationMethodJwk(
        id: verificationKeyId,
        controller: id,
        type: 'Ed25519VerificationKey2018',
        publicKeyJwk: jwk,
      );

      // For 2018/2019 specs, use publicKeyBase58 for X25519
      keyAgreement = VerificationMethodBase58(
        id: agreementKeyId,
        controller: id,
        type: 'X25519KeyAgreementKey2019',
        publicKeyBase58: base58BitcoinEncode(x25519PubKey),
      );
      break;

    case Ed25519VerificationMethodFormat.multibase2020:
      verification = VerificationMethodMultibase(
        id: verificationKeyId,
        controller: id,
        type: 'Ed25519VerificationKey2020',
        publicKeyMultibase: 'z$keyPart',
      );

      // For 2020 spec, use publicKeyMultibase for X25519
      keyAgreement = VerificationMethodMultibase(
        id: agreementKeyId,
        controller: id,
        type: 'X25519KeyAgreementKey2020',
        publicKeyMultibase: x25519PubKeyMultiBase,
      );
      break;
  }

  return DidDocument.create(
    context: Context.fromJson(context),
    id: id,
    verificationMethod: [verification, keyAgreement],
    assertionMethod: [verificationKeyId],
    keyAgreement: [agreementKeyId],
    authentication: [verificationKeyId],
    capabilityDelegation: [verificationKeyId],
    capabilityInvocation: [verificationKeyId],
  );
}

/// Builds a DID document for X25519 keys.
///
/// This function creates a DID document with a key agreement method
/// for X25519 keys.
///
/// [context] - The context list for the DID document
/// [id] - The DID identifier
/// [keyPart] - The key part of the DID
///
/// Returns a [DidDocument].
DidDocument _buildXDoc(
  List<String> context,
  String id,
  String keyPart,
) {
  var verificationKeyId = '$id#z$keyPart';
  final verification = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: 'z$keyPart',
  );
  return DidDocument.create(
    context: Context.fromJson(context),
    id: id,
    verificationMethod: [verification],
    keyAgreement: [verificationKeyId],
  );
}

/// Builds a DID document for other key types.
///
/// This function creates a DID document with a verification method
/// for various key types like P256, Secp256k1, etc.
///
/// [context] - The context list for the DID document
/// [id] - The DID identifier
/// [keyPart] - The key part of the DID
/// [type] - The key type
///
/// Returns a [DidDocument].
DidDocument _buildOtherDoc(
  List<String> context,
  String id,
  String keyPart,
  String type,
) {
  var verificationKeyId = '$id#z$keyPart';
  final verification = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: type,
    publicKeyMultibase: 'z$keyPart',
  );
  return DidDocument.create(
    context: Context.fromJson(context),
    id: id,
    verificationMethod: [verification],
    assertionMethod: [verificationKeyId],
    authentication: [verificationKeyId],
    capabilityDelegation: [verificationKeyId],
    capabilityInvocation: [verificationKeyId],
    keyAgreement: [verificationKeyId],
  );
}

/// A utility class for working with the "did:key" method.
///
/// This class provides methods to create and resolve DIDs using the "did:key" method.
class DidKey {
  /// Creates a DID document from a list of key pairs.

  static const _context = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1',
    'https://w3id.org/security/suites/x25519-2020/v1'
  ];

  static const _context2 = [
    'https://www.w3.org/ns/did/v1',
    'https://ns.did.ai/suites/multikey-2021/v1/'
  ];

  /// This method derives a key DID from a given public key
  ///
  /// [publicKey] The public key used to derive the DID
  ///
  /// Returns the DID as [String].
  ///
  /// Throws [SsiException] if the public key is invalid
  static String getDid(PublicKey publicKey) {
    final multiKey = toMultikey(publicKey.bytes, publicKey.type);
    final multibase = toMultiBase(multiKey);
    return '$_commonDidKeyPrefix$multibase';
  }

  /// This method takes a public key and creates a DID document
  ///
  /// [publicKey] The public key used to create the DID
  /// [format] The verification method format for Ed25519 keys
  ///          (defaults to multibase2020)
  ///
  /// Returns a [DidDocument].
  ///
  /// Throws [SsiException] if the public key is invalid
  static DidDocument generateDocument(
    PublicKey publicKey, {
    Ed25519VerificationMethodFormat format =
        Ed25519VerificationMethodFormat.multibase2020,
  }) {
    final multiKey = toMultikey(publicKey.bytes, publicKey.type);
    final multibase = toMultiBase(multiKey);
    final did = '$_commonDidKeyPrefix$multibase';
    return _buildDoc(multibase, did, format: format);
  }

  /// Resolves a DID string to a DID document.
  ///
  /// Supports the following key types:
  /// - Ed25519
  /// - X25519
  /// - P256
  /// - Secp256k1
  /// - P384
  /// - P521
  ///
  /// [did] - The DID string to resolve
  /// [format] The verification method format for Ed25519 keys
  ///          (defaults to multibase2020)
  ///
  /// Returns a [DidDocument]
  ///
  /// Throws [SsiException] if the Did is invalid.
  static DidDocument resolve(
    String did, {
    Ed25519VerificationMethodFormat format =
        Ed25519VerificationMethodFormat.multibase2020,
  }) {
    if (!did.startsWith('did:key')) {
      throw SsiException(
        message: 'Expected DID to start with `did:key`, got `$did` instead.',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }
    final splited = did.split(':');
    if (splited.length != 3) {
      throw SsiException(
        message: 'malformed DID: `$did`',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }

    var multibase = splited[2];
    final multibaseIndicator = multibase[0];

    if (multibaseIndicator != 'z') {
      throw SsiException(
        message: 'Only base58 (multibase `z`) encoding is supported.',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }

    return _buildDoc(multibase, did, format: format);
  }

  static DidDocument _buildDoc(
    String multibase,
    String id, {
    Ed25519VerificationMethodFormat format =
        Ed25519VerificationMethodFormat.multibase2020,
  }) {
    final keyPart = multibase.substring(1);
    if (keyPart.startsWith('6Mk')) {
      return _buildEDDoc(_context, id, keyPart, format: format);
    } else if (keyPart.startsWith('6LS')) {
      return _buildXDoc(_context, id, keyPart);
    } else if (keyPart.startsWith('Dn')) {
      return _buildOtherDoc(_context2, id, keyPart, 'P256Key2021');
    } else if (keyPart.startsWith('Q3s')) {
      return _buildOtherDoc(_context2, id, keyPart, 'Secp256k1Key2021');
    } else if (keyPart.startsWith('82')) {
      return _buildOtherDoc(_context2, id, keyPart, 'P384Key2021');
    } else if (keyPart.startsWith('2J9')) {
      return _buildOtherDoc(_context2, id, keyPart, 'P521Key2021');
    }
    throw SsiException(
      message:
          'Unsupported key type. Only Ed25519 and X25519 are fully supported.',
      code: SsiExceptionType.invalidDidKey.code,
    );
  }

  static const _commonDidKeyPrefix = 'did:key:';
}
