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
  final keysPart = did.substring(11);

  final context = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/multikey/v1'
  ];

  final verificationMethods = <EmbeddedVerificationMethod>[];
  final assertionMethod = <String>[];
  final keyAgreement = <String>[];
  final authentication = <String>[];
  final capabilityInvocation = <String>[];
  final capabilityDelegation = <String>[];
  List<ServiceEndpoint>? services;

  final elements = keysPart.split('.');
  var keyIndex = 0;
  var unnamedServiceIndex = 0;

  for (final element in elements) {
    if (element.isEmpty) continue;

    final prefix = element[0];
    final value = element.substring(1);

    switch (prefix) {
      case 'S':
        services ??= [];
        final serviceData = base64UrlNoPadDecode(value);
        final decodedJson = json.decode(utf8.decode(serviceData));
        final originalMap = jsonToMap(decodedJson);

        var serviceId = originalMap['id'];
        if (serviceId == null) {
          if (unnamedServiceIndex == 0) {
            serviceId = '#service';
          } else {
            serviceId = '#service-$unnamedServiceIndex';
          }
          unnamedServiceIndex++;
        }

        final newMap = {
          'id': serviceId,
          'type': originalMap['t'],
          'serviceEndpoint': originalMap['s']
        };
        services.add(ServiceEndpoint.fromJson(newMap));
        break;
      case 'V':
      case 'E':
      case 'A':
      case 'I':
      case 'D':
        keyIndex++;
        final kid = '#key-$keyIndex';

        final verification = VerificationMethodMultibase(
          id: kid,
          controller: did,
          type: 'Multikey',
          publicKeyMultibase: value,
        );
        verificationMethods.add(verification);

        if (prefix == 'V') authentication.add(kid);
        if (prefix == 'E') keyAgreement.add(kid);
        if (prefix == 'A') assertionMethod.add(kid);
        if (prefix == 'I') capabilityInvocation.add(kid);
        if (prefix == 'D') capabilityDelegation.add(kid);
        break;
      default:
        throw SsiException(
          message: 'Unknown prefix `$prefix` in peer DID.',
          code: SsiExceptionType.invalidDidPeer.code,
        );
    }
  }

  return DidDocument.create(
    context: Context.fromJson(context),
    id: did,
    verificationMethod: verificationMethods,
    assertionMethod: assertionMethod,
    keyAgreement: keyAgreement,
    authentication: authentication,
    capabilityInvocation: capabilityInvocation,
    capabilityDelegation: capabilityDelegation,
    service: services,
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

  static String _buildServiceEncoded(List<ServiceEndpoint>? services) {
    if (services == null || services.isEmpty) {
      return '';
    }

    return services.map((service) {
      final dynamic endpointValue;
      final serviceValue = service.serviceEndpoint;
      switch (serviceValue) {
        case StringEndpoint(:final url):
          endpointValue = url;
        case MapEndpoint(:final data):
          endpointValue = data;
        case SetEndpoint():
          throw SsiException(
            message:
                'did:peer does not support set-based service endpoints in the DID URL',
            code: SsiExceptionType.invalidDidDocument.code,
          );
      }

      final serviceJson = {
        'id': service.id,
        't': service.type,
        's': endpointValue,
      };

      final jsonToEncode = json.encode(serviceJson);
      final encodedService = base64UrlNoPadEncode(utf8.encode(jsonToEncode));
      return '.${Numalgo2Prefix.service.value}$encodedService';
    }).join('');
  }

  static String _pubKeysToPeerDid(List<PublicKey> signingKeys,
      [List<PublicKey>? agreementKeys,
      List<ServiceEndpoint>? serviceEndpoints]) {
    var isDid0 = signingKeys.length == 1 &&
        (agreementKeys == null || agreementKeys.isEmpty) &&
        (serviceEndpoints == null || serviceEndpoints.isEmpty);

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
    var serviceStr = _buildServiceEncoded(serviceEndpoints);

    return '${_didTypePrefixes[DidPeerType.peer2]}$authKeysStr$agreementKeysStr$serviceStr';
  }

  /// This method derives the peer DID from the given public keys
  ///
  /// [authenticationKeys] The authentication keys used to derive the DID
  /// [keyAgreementKeys] The key agreement keys used to derive the DID
  /// [serviceEndpoints] - Optional list of service endpoints.
  ///
  /// Returns the DID as [String].
  ///
  /// Throws [SsiException] if the public key is invalid
  static String getDid(
    List<PublicKey> authenticationKeys,
    List<PublicKey> keyAgreementKeys, {
    List<ServiceEndpoint>? serviceEndpoints,
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
        (serviceEndpoints == null || serviceEndpoints.isEmpty);

    if (isDid0) {
      return _pubKeysToPeerDid(authenticationKeys);
    } else {
      return _pubKeysToPeerDid(
          authenticationKeys, keyAgreementKeys, serviceEndpoints);
    }
  }

  /// Creates a DID Document for a list of key pairs.
  ///
  /// authenticationKeys - The list of authentication keys.
  /// keyAgreementKeys - The list of key agreement keys.
  /// serviceEndpoints - Optional list of service endpoints.
  ///
  /// Returns a [DidDocument].
  ///
  /// Throws an [SsiException] if empty key pairs.
  static DidDocument generateDocument(
    List<PublicKey> authenticationKeys,
    List<PublicKey> keyAgreementKeys, {
    List<ServiceEndpoint>? serviceEndpoints,
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
        serviceEndpoints: serviceEndpoints);

    // For did:peer:0, use original single-key logic
    if (authenticationKeys.length == 1 &&
        keyAgreementKeys.isEmpty &&
        (serviceEndpoints == null || serviceEndpoints.isEmpty)) {
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

    var keyIndex = 0;

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

    return DidDocument.create(
      context: Context.fromJson(context),
      id: did,
      verificationMethod: verificationMethods,
      authentication: authenticationRefs,
      keyAgreement: keyAgreementRefs,
      service: serviceEndpoints,
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
