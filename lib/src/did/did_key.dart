import 'package:base_codecs/base_codecs.dart';
import 'public_key_utils.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../key_pair/key_pair.dart';
import '../utility.dart';
import 'did_document.dart';

/// Builds a DID document for Ed25519 keys.
///
/// This function creates a DID document with both verification and key agreement methods
/// by converting the Ed25519 public key to an X25519 key.
///
/// [context] - The context list for the DID document
/// [id] - The DID identifier
/// [keyPart] - The key part of the DID
///
/// Returns a [DidDocument]
///
/// Throws [SsiException] if the conversion fails.
Future<DidDocument> _buildEDDoc(
  List<String> context,
  String id,
  String keyPart,
) {
  final multiCodecXKey = ed25519PublicToX25519Public(
    base58Bitcoin.decode(keyPart).sublist(2),
  );
  if (!multiCodecXKey.startsWith('6LS')) {
    throw SsiException(
      message:
          'Something went wrong during conversion from Ed25515 to curve25519 key',
      code: SsiExceptionType.invalidDidKey.code,
    );
  }
  String verificationKeyId = '$id#z$keyPart';
  String agreementKeyId = '$id#z$multiCodecXKey';

  final verification = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: 'z$keyPart',
  );
  final keyAgreement = VerificationMethodMultibase(
    id: agreementKeyId,
    controller: id,
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: 'z$multiCodecXKey',
  );

  return Future.value(
    DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification, keyAgreement],
      assertionMethod: [verificationKeyId],
      keyAgreement: [agreementKeyId],
      authentication: [verificationKeyId],
      capabilityDelegation: [verificationKeyId],
      capabilityInvocation: [verificationKeyId],
    ),
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
Future<DidDocument> _buildXDoc(
  List<String> context,
  String id,
  String keyPart,
) {
  String verificationKeyId = '$id#z$keyPart';
  final verification = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: 'z$keyPart',
  );
  return Future.value(
    DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification],
      keyAgreement: [verificationKeyId],
    ),
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
Future<DidDocument> _buildOtherDoc(
  List<String> context,
  String id,
  String keyPart,
  String type,
) {
  String verificationKeyId = '$id#z$keyPart';
  final verification = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: type,
    publicKeyMultibase: 'z$keyPart',
  );
  return Future.value(
    DidDocument(
      context: context,
      id: id,
      verificationMethod: [verification],
      assertionMethod: [verificationKeyId],
      authentication: [verificationKeyId],
      capabilityDelegation: [verificationKeyId],
      capabilityInvocation: [verificationKeyId],
      keyAgreement: [verificationKeyId],
    ),
  );
}

/// A utility class for working with the "did:key" method.
///
/// This class provides methods to create and resolve DIDs using the "did:key" method.
class DidKey {
  /// Creates a DID document from a list of key pairs.
  ///
  /// This method takes a list of key pairs and creates a DID document using the
  /// first key pair in the list.
  ///
  /// [keyPairs] A list of key pairs, where the first one will be used to create the DID
  ///
  /// Returns a [DidDocument].
  ///
  /// Throws [SsiException] if the key pair is invalid
  static Future<DidDocument> create(List<KeyPair> keyPairs) async {
    if (keyPairs.isEmpty) {
      throw SsiException(
        message: 'At least one key pair is required to create a DID',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }
    final keyPair = keyPairs[0];
    final keyType = await keyPair.publicKeyType;
    final publicKey = await keyPair.publicKey;
    final multiKey = toMultikey(publicKey, keyType);
    final multibase = toMultiBase(multiKey);
    final did = '$commonDidKeyPrefix$multibase';
    final keyId = '$did#$multibase';

    // FIXME(FTL-20741) double check the doc
    return DidDocument(
      id: did,
      verificationMethod: [
        VerificationMethodMultibase(
          id: keyId,
          controller: did,
          type: 'Multikey',
          publicKeyMultibase: multibase,
        )
      ],
      authentication: [keyId],
      assertionMethod: [keyId],
      capabilityInvocation: [keyId],
      capabilityDelegation: [keyId],
    );
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
  ///
  /// Returns a [DidDocument]
  ///
  /// Throws [SsiException] if the Did is invalid.
  static Future<DidDocument> resolve(String did) {
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

    String keyPart = splited[2];
    final multibaseIndicator = keyPart[0];
    keyPart = keyPart.substring(1);

    final context = [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
      "https://w3id.org/security/suites/x25519-2020/v1"
    ];

    final context2 = [
      "https://www.w3.org/ns/did/v1",
      'https://ns.did.ai/suites/multikey-2021/v1/'
    ];

    final id = did;

    if (multibaseIndicator != 'z') {
      throw SsiException(
        message: 'Only base58 (multibase `z`) encoding is supported.',
        code: SsiExceptionType.invalidDidKey.code,
      );
    }

    if (keyPart.startsWith('6Mk')) {
      return _buildEDDoc(context, id, keyPart);
    } else if (keyPart.startsWith('6LS')) {
      return _buildXDoc(context, id, keyPart);
    } else if (keyPart.startsWith('Dn')) {
      return _buildOtherDoc(context2, id, keyPart, 'P256Key2021');
    } else if (keyPart.startsWith('Q3s')) {
      return _buildOtherDoc(context2, id, keyPart, 'Secp256k1Key2021');
    } else if (keyPart.startsWith('82')) {
      return _buildOtherDoc(context2, id, keyPart, 'P384Key2021');
    } else if (keyPart.startsWith('2J9')) {
      return _buildOtherDoc(context2, id, keyPart, 'P521Key2021');
    }
    throw SsiException(
      message:
          'Unsupported key type. Only Ed25519 and X25519 are fully supported.',
      code: SsiExceptionType.invalidDidKey.code,
    );
  }

  static const commonDidKeyPrefix = 'did:key:';
}
