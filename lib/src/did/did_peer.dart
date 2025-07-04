import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../json_ld/context.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import '../utility.dart';
import 'did_document/index.dart';
import 'public_key_utils.dart';

/// Enum representing the prefixes used in encoding for peer DIDs.
///
/// These prefixes are used to identify different components in a peer DID:
/// - [authentication] - Used for authentication keys (prefix "V")
/// - [keyAgreement] - Used for key agreement keys (prefix "E")
/// - [service] - Used for service endpoints (prefix "S")

enum Numalgo2Prefix {
  /// Prefix for authentication keys.
  authentication('V'),

  /// Prefix for key agreement keys.
  keyAgreement('E'),

  /// Prefix for service entries.
  service('S');

  /// String value of the prefix.
  final String value;

  /// Creates a new [Numalgo2Prefix] instance.
  ///
  /// [value] - The string value of the prefix.
  const Numalgo2Prefix(this.value);
}

/// Regular expression pattern for matching peer DIDs.
final RegExp peerDIDPattern = RegExp(
    r'^did:peer:((0(z)[1-9a-km-zA-HJ-NP-Z]+)|(2(\.[AEVID](z)[1-9a-km-zA-HJ-NP-Z]+)+)+(\.(S)[0-9a-zA-Z]*)?)');

/// Validates if a given string matches the peer DID pattern.
///
/// [peerDID] - The string to validate.
///
/// Returns `true` if the string matches the peer DID pattern, `false` otherwise.
bool isPeerDID(String peerDID) {
  return peerDIDPattern.hasMatch(peerDID);
}

/// Resolves a numalgo0 peer DID to a DID document.
///
/// Supports only Base58 encoded keys.
DidDocument _resolveDidPeer0(String did) {
  final multibaseIndicator = did[10];

  if (multibaseIndicator != 'z') {
    throw SsiException(
      message: 'Only Base58 is supported yet',
      code: SsiExceptionType.invalidDidPeer.code,
    );
  }

  final contextEdward = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1'
  ];
  const contextEdX = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/x25519-2020/v1'
  ];

  const contextMultikey = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/multikey-2021/v1',
  ];

  var keyPart = did.substring(11);

  if (keyPart.startsWith('6Mk')) {
    return _buildEDDoc(contextEdward, did, keyPart);
  } else if (keyPart.startsWith('6LS')) {
    return _buildXDoc(contextEdX, did, keyPart);
  } else if (keyPart.startsWith('Dn')) {
    return _buildMultikeyDoc(
      contextMultikey,
      did,
      keyPart,
    );
  } else if (keyPart.startsWith('Q3s')) {
    return _buildMultikeyDoc(
      contextMultikey,
      did,
      keyPart,
    );
  } else if (keyPart.startsWith('82')) {
    return _buildMultikeyDoc(
      contextMultikey,
      did,
      keyPart,
    );
  } else if (keyPart.startsWith('2J9')) {
    return _buildMultikeyDoc(
      contextMultikey,
      did,
      keyPart,
    );
  } else {
    throw SsiException(
      message: 'Only Ed25519 and X25519 keys are supported now',
      code: SsiExceptionType.unsupportedSignatureScheme.code,
    );
  }
}

/// Resolves a numalgo2 peer DID to a DID document.
DidDocument _resolveDidPeer2(String did) {
  var keysPart = did.substring(11);

  var authenticationKeys = <String>[];
  var agreementKeys = <String>[];
  String? serviceString;

  final keys = keysPart.split('.');
  for (final key in keys) {
    final prefix = key[0];
    final keyPart = key.substring(1);
    switch (prefix) {
      case 'S':
        serviceString = keyPart;
        break;
      case 'V':
        authenticationKeys.add(keyPart);
        break;
      case 'E':
        agreementKeys.add(keyPart);
        break;
      default:
        throw SsiException(
          message: 'Unknown prefix `$prefix` in peer DID.',
          code: SsiExceptionType.invalidDidPeer.code,
        );
    }
  }

  return _buildMultiKeysDoc(
      did, agreementKeys, authenticationKeys, serviceString);
}

/// Builds a DID document for a multi-key peer DID.
///
/// [did] - The DID identifier.
/// [agreementKeys] - The list of agreement keys.
/// [authenticationKeys] - The list of authentication keys.
/// [serviceStr] - The service string.
///
/// Returns a [DidDocument].
DidDocument _buildMultiKeysDoc(String did, List<String> agreementKeys,
    List<String> authenticationKeys, String? serviceStr) {
  final context = [
    'https://www.w3.org/ns/did/v1',
    'https://ns.did.ai/suites/multikey-2021/v1/',
  ];

  var verificationMethod = <EmbeddedVerificationMethod>[];
  var assertionMethod = <String>[];
  var keyAgreement = <String>[];
  var authentication = <String>[];

  List<ServiceEndpoint>? service;
  if (serviceStr != null) {
    var paddingNeeded = (4 - serviceStr.length % 4) % 4;
    var padded = serviceStr + ('=' * paddingNeeded);

    var serviceList = base64Decode(padded);
    final serviceJson = json.decode(utf8.decode(serviceList));
    serviceJson['serviceEndpoint'] = serviceJson['s'];
    serviceJson['accept'] = serviceJson['a'];
    serviceJson['type'] = serviceJson['t'];
    if (serviceJson['type'] == 'dm') {
      serviceJson['type'] = 'DIDCommMessaging';
    }
    service = [ServiceEndpoint.fromJson(serviceJson)];
  }

  var i = 0;

  for (final agreementKey in agreementKeys) {
    i++;

    var kid = '#key-$i';
    final verification = VerificationMethodMultibase(
      id: kid,
      controller: did,
      type: 'Multikey',
      publicKeyMultibase: agreementKey,
    );

    verificationMethod.add(verification);
    keyAgreement.add(kid);
  }

  for (final authenticationKey in authenticationKeys) {
    i++;

    var kid = '#key-$i';
    final verification = VerificationMethodMultibase(
      id: kid,
      controller: did,
      type: 'Multikey',
      publicKeyMultibase: authenticationKey,
    );

    verificationMethod.add(verification);
    assertionMethod.add(kid);
    authentication.add(kid);
  }

  return DidDocument.create(
    context: Context.fromJson(context),
    id: did,
    verificationMethod: verificationMethod,
    assertionMethod: assertionMethod,
    keyAgreement: keyAgreement,
    authentication: authentication,
    service: service,
  );
}

/// Builds a DID Document for ED25519 keys.
DidDocument _buildEDDoc(
  List<String> context,
  String id,
  String keyPart,
) {
  final x25519PubKey =
      ed25519PublicToX25519Public(base58Bitcoin.decode(keyPart).sublist(2));
  final x25519PubKeyMultiBase = toMultiBase(
    toMultikey(x25519PubKey, KeyType.x25519),
  );

  final verificationKeyId = '$id#$keyPart';
  final agreementKeyId = '$id#$x25519PubKeyMultiBase';

  final verificationMethod = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: 'z$keyPart',
  );

  final keyAgreementMethod = VerificationMethodMultibase(
    id: agreementKeyId,
    controller: id,
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: x25519PubKeyMultiBase,
  );

  return DidDocument.create(
    context: Context.fromJson(context),
    id: id,
    verificationMethod: [verificationMethod, keyAgreementMethod],
    assertionMethod: [verificationKeyId],
    keyAgreement: [agreementKeyId],
    authentication: [verificationKeyId],
    capabilityDelegation: [verificationKeyId],
    capabilityInvocation: [verificationKeyId],
  );
}

/// Builds a DID Document for X25519 keys.
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

/// Builds a DID Document for a Multikey-based key (P256, Secp256k1, P384, P521, etc.).
DidDocument _buildMultikeyDoc(
  List<String> context,
  String id,
  String keyPart,
) {
  final verificationKeyId = '$id#z$keyPart';
  final verificationMethod = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: 'Multikey',
    publicKeyMultibase: 'z$keyPart',
  );

  return DidDocument.create(
    context: Context.fromJson(context),
    id: id,
    verificationMethod: [verificationMethod],
    assertionMethod: [verificationKeyId],
    authentication: [verificationKeyId],
    capabilityDelegation: [verificationKeyId],
    capabilityInvocation: [verificationKeyId],
  );
}

/// A utility class for working with the "did:peer" method.
///
/// This class provides methods to create and resolve DIDs using the "did:peer" method.
class DidPeer {
  /// Determines the type of a DID based on its prefix.
  ///
  /// [did] - The DID to determine the type of.
  ///
  /// Returns a [DidPeerType].
  ///
  /// Throws an [SsiException] if the DID is not a valid peer DID.
  static DidPeerType determineType(String did) {
    for (final entry in _didTypePrefixes.entries) {
      if (did.startsWith(entry.value)) {
        return entry.key;
      }
    }
    throw SsiException(
      message: 'Unknown did peer type `$did`',
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }

  static String _buildServiceEncoded(String? serviceEndpoint) {
    if (serviceEndpoint == null) {
      return '';
    }

    var jsonString = json.encode({
      'id': 'new-id',
      't': 'dm', // "type": "DIDCommMessaging"
      's': serviceEndpoint, // serviceEndpoint
      'a': ['didcomm/v2'], // accept
    });

    return ".${Numalgo2Prefix.service.value}${base64UrlEncode(utf8.encode(jsonString)).replaceAll('=', '')}";
  }

  static String _pubKeysToPeerDid(List<PublicKey> signingKeys,
      [List<PublicKey>? agreementKeys, String? serviceEndpoint]) {
    var isDid0 = signingKeys.length == 1 &&
        (agreementKeys == null && serviceEndpoint == null);

    if (isDid0) {
      var signingKey = signingKeys[0];
      final multibase = toMultiBase(
        toMultikey(signingKey.bytes, signingKey.type),
      );
      return '${_didTypePrefixes[DidPeerType.peer0]}$multibase';
    }

    var encSep = '.${Numalgo2Prefix.keyAgreement.value}';
    var authSep = '.${Numalgo2Prefix.authentication.value}';

    var isAgreementNotEmpty = agreementKeys != null && agreementKeys.isNotEmpty;

    var agreementKeysStr = isAgreementNotEmpty
        ? encSep +
            agreementKeys
                .map(
                  (key) => toMultiBase(
                    toMultikey(key.bytes, key.type),
                  ),
                )
                .join(encSep)
        : '';
    var authKeysStr = signingKeys.isNotEmpty
        ? authSep +
            signingKeys
                .map(
                  (key) => toMultiBase(
                    toMultikey(key.bytes, key.type),
                  ),
                )
                .join(authSep)
        : '';
    var serviceStr = _buildServiceEncoded(serviceEndpoint);

    return '${_didTypePrefixes[DidPeerType.peer2]}$agreementKeysStr$authKeysStr$serviceStr';
  }

  /// This method derives the peer DID from the given public keys
  ///
  /// [publicKeys] The public keys used to derive the DID
  /// [serviceEndpoint] - Optional service endpoint.
  ///
  /// Returns the DID as [String].
  ///
  /// Throws [SsiException] if the public key is invalid
  static String getDid(
    List<PublicKey> publicKeys, {
    String? serviceEndpoint,
  }) {
    if (publicKeys.isEmpty) {
      throw SsiException(
        message: 'At least one key must be provided',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
    // bool isDid0 = keyPairs.length == 1 && serviceEndpoint == null;
    var didType = publicKeys.length == 1 && serviceEndpoint == null
        ? DidPeerType.peer0
        : DidPeerType.peer2;

    if (didType != DidPeerType.peer0) {
      return _pubKeysToPeerDid(publicKeys, publicKeys, serviceEndpoint);
    } else {
      return _pubKeysToPeerDid(publicKeys);
    }
  }

  /// Creates a DID Document for a list of key pairs.
  ///
  /// keys - The list of public keys.
  /// serviceEndpoint - Optional service endpoint.
  ///
  /// Returns a [DidDocument].
  ///
  /// Throws an [SsiException] if empty key pairs.
  //FIXME(FTL-20741) should match resolve (i.e one parameter for each entry in Numalgo2Prefix)
  static DidDocument generateDocument(
    List<PublicKey> keys, {
    String? serviceEndpoint,
  }) {
    final did = getDid(keys, serviceEndpoint: serviceEndpoint);

    final verificationMethods = <EmbeddedVerificationMethod>[];
    for (var i = 0; i < keys.length; i++) {
      final key = keys[i];
      verificationMethods.add(
        VerificationMethodMultibase(
          id: did,
          controller: 'key$i', // FIXME(FTL-20741) should come from the outside
          type: 'Multikey',
          publicKeyMultibase: toMultiBase(
            toMultikey(
              key.bytes,
              key.type,
            ),
          ),
        ),
      );
    }

    // FIXME(FTL-20741) should match arguments
    final keyId = verificationMethods[0].id;
    return DidDocument.create(
      id: did,
      verificationMethod: verificationMethods,
      authentication: [keyId],
      assertionMethod: [keyId],
      capabilityInvocation: [keyId],
      capabilityDelegation: [keyId],
    );
  }

  /// Resolves a peer DID to a DID document.
  ///
  /// [did] - The peer DID to resolve.
  ///
  /// Returns a [DidDocument].
  ///
  /// Throws [SsiException] if the DID is not a valid peer DID.
  static DidDocument resolve(String did) {
    if (!isPeerDID(did)) {
      throw SsiException(
        message: '`$did` Does not match peer DID regexp.',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    var isPeer0 = did[9] == '0';
    if (isPeer0) {
      return _resolveDidPeer0(did);
    } else {
      return _resolveDidPeer2(did);
    }
  }

  // static const Map<KeyType, String> _keyTypePrefixes = {
  //   KeyType.x25519: '6LS',
  //   KeyType.ed25519: '6Mk',
  // };

  static const Map<DidPeerType, String> _didTypePrefixes = {
    DidPeerType.peer0: 'did:peer:0',
    DidPeerType.peer2: 'did:peer:2',
  };
}
