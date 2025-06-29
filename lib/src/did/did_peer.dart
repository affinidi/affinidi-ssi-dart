import 'dart:convert';

import 'package:base_codecs/base_codecs.dart';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../json_ld/context.dart';
import '../key_pair/public_key.dart';
import '../types.dart';
import '../util/base64_util.dart';
import '../util/json_util.dart';
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

  var keyPart = did.substring(11);

  if (keyPart.startsWith('6Mk')) {
    return _buildEDDoc(contextEdward, did, keyPart);
  } else if (keyPart.startsWith('6LS')) {
    return _buildXDoc(contextEdX, did, keyPart);
    // } else if (keyPart.startsWith('Dn')) {
    //   return _buildOtherDoc(context2, id, keyPart, 'P256Key2021');
    // } else if (keyPart.startsWith('Q3s')) {
    //   return _buildOtherDoc(context2, id, keyPart, 'Secp256k1Key2021');
    // } else if (keyPart.startsWith('82')) {
    //   return _buildOtherDoc(context2, id, keyPart, 'P384Key2021');
    // } else if (keyPart.startsWith('2J9')) {
    //   return _buildOtherDoc(context2, id, keyPart, 'P521Key2021');
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
    'https://ns.did.ai/suites/multikey-2021/v1/'
  ];

  var verificationMethod = <EmbeddedVerificationMethod>[];
  var assertionMethod = <String>[];
  var keyAgreement = <String>[];
  var authentication = <String>[];

  List<ServiceEndpoint>? service;
  if (serviceStr != null) {
    // Use base64UrlNoPadDecode which handles padding automatically
    var serviceList = base64UrlNoPadDecode(serviceStr);
    final serviceJson = jsonToMap(utf8.decode(serviceList));
    serviceJson['serviceEndpoint'] = serviceJson['s'];
    serviceJson['accept'] = serviceJson['a'];
    serviceJson['type'] = serviceJson['t'];
    service = [ServiceEndpoint.fromJson(serviceJson)];
  }

  var i = 0;

  for (final agreementKey in agreementKeys) {
    i++;
    final type = agreementKey.startsWith('z6LS')
        ? 'X25519KeyAgreementKey2020'
        : 'Ed25519VerificationKey2020';

    var kid = '#key-$i';
    final verification = VerificationMethodMultibase(
      id: kid,
      controller: did,
      type: type, // Multikey ?
      publicKeyMultibase: agreementKey,
    );

    verificationMethod.add(verification);
    keyAgreement.add(kid);
  }

  for (final authenticationKey in authenticationKeys) {
    i++;
    final type = authenticationKey.startsWith('z6LS')
        ? 'X25519KeyAgreementKey2020'
        : 'Ed25519VerificationKey2020';

    var kid = '#key-$i';
    final verification = VerificationMethodMultibase(
      id: kid,
      controller: did,
      type: type, // Multikey ?
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
  final multiCodecXKey =
      ed25519PublicToX25519Public(base58Bitcoin.decode(keyPart).sublist(2));
  if (!multiCodecXKey.startsWith('6LS')) {
    throw SsiException(
      message: 'Something went wrong during conversion',
      code: SsiExceptionType.invalidDidPeer.code,
    );
  }

  var verificationKeyId = '$id#$keyPart';
  var agreementKeyId = '$id#z$multiCodecXKey';

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
    publicKeyMultibase: 'z$multiCodecXKey',
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

  static String _buildServiceEncoded(ServiceEndpointValue? serviceValue) {
    if (serviceValue == null) {
      return '';
    }

    final Map<String, dynamic> serviceJson;
    switch (serviceValue) {
      case StringEndpoint(:final url):
        // For string endpoints, create a generic service structure
        serviceJson = {
          'id': randomId(),
          't': 'GenericService', // "type": "GenericService"
          's': url, // serviceEndpoint
          'a': ['application/json'], // accept
        };
      case MapEndpoint(:final data):
        // For map data, preserve the structure
        serviceJson = {
          'id': data['id'] ?? randomId(),
          't': data['t'] ?? data['type'] ?? 'GenericService',
          ...data,
        };
      case SetEndpoint():
        // did:peer URIs cannot encode sets
        throw SsiException(
          message:
              'did:peer does not support set-based service endpoints in the DID URL',
          code: SsiExceptionType.invalidDidDocument.code,
        );
    }

    return '.${Numalgo2Prefix.service.value}${base64UrlNoPadEncode(utf8.encode(json.encode(serviceJson)))}';
  }

  static String _pubKeysToPeerDid(List<PublicKey> signingKeys,
      [List<PublicKey>? agreementKeys, ServiceEndpointValue? serviceEndpoint]) {
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
  /// [authenticationKeys] The authentication keys used to derive the DID
  /// [keyAgreementKeys] The key agreement keys used to derive the DID
  /// [serviceEndpoint] - Optional service endpoint data.
  ///
  /// Returns the DID as [String].
  ///
  /// Throws [SsiException] if the public key is invalid
  static String getDid(
    List<PublicKey> authenticationKeys,
    List<PublicKey> keyAgreementKeys, {
    ServiceEndpointValue? serviceEndpoint,
  }) {
    if (authenticationKeys.isEmpty && keyAgreementKeys.isEmpty) {
      throw SsiException(
        message: 'At least one key must be provided',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // did:peer:0 is only for single authentication key with no agreement keys or service
    var isDid0 = authenticationKeys.length == 1 &&
        keyAgreementKeys.isEmpty &&
        serviceEndpoint == null;

    if (isDid0) {
      return _pubKeysToPeerDid(authenticationKeys);
    } else {
      return _pubKeysToPeerDid(
          authenticationKeys, keyAgreementKeys, serviceEndpoint);
    }
  }

  /// Creates a DID Document for a list of key pairs.
  ///
  /// authenticationKeys - The list of authentication keys.
  /// keyAgreementKeys - The list of key agreement keys.
  /// serviceEndpoint - Optional service endpoint data.
  ///
  /// Returns a [DidDocument].
  ///
  /// Throws an [SsiException] if empty key pairs.
  static DidDocument generateDocument(
    List<PublicKey> authenticationKeys,
    List<PublicKey> keyAgreementKeys, {
    ServiceEndpointValue? serviceEndpoint,
  }) {
    // Validate input
    if (authenticationKeys.isEmpty && keyAgreementKeys.isEmpty) {
      throw SsiException(
        message: 'At least one key must be provided',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Generate the DID
    final did = getDid(authenticationKeys, keyAgreementKeys,
        serviceEndpoint: serviceEndpoint);

    // For did:peer:0, use original single-key logic
    if (authenticationKeys.length == 1 &&
        keyAgreementKeys.isEmpty &&
        serviceEndpoint == null) {
      final key = authenticationKeys[0];
      final verificationMethod = VerificationMethodMultibase(
        id: did,
        controller: did,
        type: 'Multikey',
        publicKeyMultibase: toMultiBase(
          toMultikey(key.bytes, key.type),
        ),
      );

      return DidDocument.create(
        id: did,
        verificationMethod: [verificationMethod],
        authentication: [did],
        assertionMethod: [did],
        capabilityInvocation: [did],
        capabilityDelegation: [did],
      );
    }

    // For did:peer:2, build document with proper key separation
    final context = [
      'https://www.w3.org/ns/did/v1',
      'https://ns.did.ai/suites/multikey-2021/v1/'
    ];

    final verificationMethods = <EmbeddedVerificationMethod>[];
    final keyAgreementRefs = <String>[];
    final authenticationRefs = <String>[];

    // Handle service endpoint
    List<ServiceEndpoint>? service;
    if (serviceEndpoint != null) {
      final serviceStr = _buildServiceEncoded(serviceEndpoint);
      if (serviceStr.isNotEmpty) {
        var serviceList = base64UrlNoPadDecode(serviceStr.substring(2));
        final serviceJson = jsonToMap(utf8.decode(serviceList));
        serviceJson['serviceEndpoint'] = serviceJson['s'];
        serviceJson['accept'] = serviceJson['a'];
        serviceJson['type'] = serviceJson['t'];
        service = [ServiceEndpoint.fromJson(serviceJson)];
      }
    }

    var keyIndex = 0;

    for (final key in keyAgreementKeys) {
      keyIndex++;
      final keyId = '#key-$keyIndex';

      final keyType = key.type == KeyType.x25519
          ? 'X25519KeyAgreementKey2020'
          : 'Ed25519VerificationKey2020';

      final verificationMethod = VerificationMethodMultibase(
        id: keyId,
        controller: did,
        type: keyType,
        publicKeyMultibase: toMultiBase(
          toMultikey(key.bytes, key.type),
        ),
      );

      verificationMethods.add(verificationMethod);
      keyAgreementRefs.add(keyId);
    }

    // Add authentication keys (V prefix in the DID)
    for (final key in authenticationKeys) {
      keyIndex++;
      final keyId = '#key-$keyIndex';

      final keyType = key.type == KeyType.x25519
          ? 'X25519KeyAgreementKey2020'
          : 'Ed25519VerificationKey2020';

      final verificationMethod = VerificationMethodMultibase(
        id: keyId,
        controller: did,
        type: keyType,
        publicKeyMultibase: toMultiBase(
          toMultikey(key.bytes, key.type),
        ),
      );

      verificationMethods.add(verificationMethod);
      authenticationRefs.add(keyId);
    }

    return DidDocument.create(
      context: Context.fromJson(context),
      id: did,
      verificationMethod: verificationMethods,
      authentication: authenticationRefs,
      assertionMethod: authenticationRefs,
      keyAgreement: keyAgreementRefs,
      capabilityInvocation: authenticationRefs,
      capabilityDelegation: authenticationRefs,
      service: service,
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
