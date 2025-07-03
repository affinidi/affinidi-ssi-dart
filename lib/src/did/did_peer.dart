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
import 'did_controller/verification_relationship.dart';
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
  service('S'),

  /// Prefix for assertion keys.
  assertion('A'),

  /// Prefix for capability invocation keys.
  capabilityInvocation('I'),

  /// Prefix for capability delegation keys.
  capabilityDelegation('D');

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
      'P256Key2021',
    );
  } else if (keyPart.startsWith('Q3s')) {
    return _buildMultikeyDoc(
      contextMultikey,
      did,
      keyPart,
      'Secp256k1Key2021',
    );
  } else if (keyPart.startsWith('82')) {
    return _buildMultikeyDoc(
      contextMultikey,
      did,
      keyPart,
      'P384Key2021',
    );
  } else if (keyPart.startsWith('2J9')) {
    return _buildMultikeyDoc(
      contextMultikey,
      did,
      keyPart,
      'P521Key2021',
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
  final seenKeys = <String, String>{}; // multibase -> kid

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
        final String kid;
        if (seenKeys.containsKey(value)) {
          kid = seenKeys[value]!;
        } else {
          keyIndex++;
          kid = '#key-$keyIndex';
          seenKeys[value] = kid;
          final verification = VerificationMethodMultibase(
            id: kid,
            controller: did,
            type: 'Multikey',
            publicKeyMultibase: value,
          );
          verificationMethods.add(verification);
        }

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
  final x25519PubKey =
      ed25519PublicToX25519Public(base58Bitcoin.decode(keyPart).sublist(2));
  final x25519PubKeyMultiBase = toMultiBase(
    toMultikey(x25519PubKey, KeyType.x25519),
  );

  var verificationKeyId = id;
  var agreementKeyId = '$id#$x25519PubKeyMultiBase';

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
  var verificationKeyId = id;
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
  String keyType,
) {
  final verificationKeyId = '$id#$keyPart';
  final verificationMethod = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: keyType,
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

  /// This method derives the peer DID from the given public keys
  ///
  /// [verificationMethods] The list of all public keys in the document.
  /// [relationships] A map defining which keys are used for which purpose.
  /// [serviceEndpoints] - Optional list of service endpoints.
  ///
  /// Returns the DID as [String].
  ///
  /// Throws [SsiException] if the public key is invalid
  static String getDid({
    required List<PublicKey> verificationMethods,
    Map<VerificationRelationship, List<int>>? relationships,
    List<ServiceEndpoint>? serviceEndpoints,
  }) {
    if (verificationMethods.isEmpty) {
      throw SsiException(
        message: 'At least one key must be provided',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    final rels = relationships ?? {};
    final authIdx = rels[VerificationRelationship.authentication] ?? [];
    final kaIdx = rels[VerificationRelationship.keyAgreement] ?? [];
    final amIdx = rels[VerificationRelationship.assertionMethod] ?? [];
    final ciIdx = rels[VerificationRelationship.capabilityInvocation] ?? [];
    final cdIdx = rels[VerificationRelationship.capabilityDelegation] ?? [];

    // did:peer:0 is for a single key used only for authentication
    final isDid0 = verificationMethods.length == 1 &&
        authIdx.length == 1 &&
        authIdx.first == 0 &&
        kaIdx.isEmpty &&
        amIdx.isEmpty &&
        ciIdx.isEmpty &&
        cdIdx.isEmpty &&
        (serviceEndpoints == null || serviceEndpoints.isEmpty);

    if (isDid0) {
      final signingKey = verificationMethods[0];
      final multibase = toMultiBase(
        toMultikey(signingKey.bytes, signingKey.type),
      );
      return '${_didTypePrefixes[DidPeerType.peer0]}$multibase';
    }

    String buildKeyString(List<int> keyIndexes, Numalgo2Prefix prefix) {
      if (keyIndexes.isEmpty) return '';
      final separator = '.${prefix.value}';
      return separator +
          keyIndexes
              .map((i) => toMultiBase(toMultikey(
                  verificationMethods[i].bytes, verificationMethods[i].type)))
              .join(separator);
    }

    final authKeysStr = buildKeyString(authIdx, Numalgo2Prefix.authentication);
    final agreementKeysStr = buildKeyString(kaIdx, Numalgo2Prefix.keyAgreement);
    final assertionKeysStr = buildKeyString(amIdx, Numalgo2Prefix.assertion);
    final capabilityInvocationKeysStr =
        buildKeyString(ciIdx, Numalgo2Prefix.capabilityInvocation);
    final capabilityDelegationKeysStr =
        buildKeyString(cdIdx, Numalgo2Prefix.capabilityDelegation);

    final serviceStr = _buildServiceEncoded(serviceEndpoints);

    return '${_didTypePrefixes[DidPeerType.peer2]}'
        '$authKeysStr'
        '$agreementKeysStr'
        '$capabilityInvocationKeysStr'
        '$capabilityDelegationKeysStr'
        '$assertionKeysStr'
        '$serviceStr';
  }

  /// Creates a DID Document from a list of public keys and their purposes.
  ///
  /// [verificationMethods] The list of all public keys in the document.
  /// [relationships] A map defining which keys are used for which purpose.
  /// [serviceEndpoints] - Optional list of service endpoints.
  ///
  /// Returns a [DidDocument].
  ///
  /// Throws an [SsiException] if no keys are provided.
  static DidDocument generateDocument({
    required List<PublicKey> verificationMethods,
    Map<VerificationRelationship, List<int>>? relationships,
    List<ServiceEndpoint>? serviceEndpoints,
  }) {
    if (verificationMethods.isEmpty) {
      throw SsiException(
        message: 'At least one key must be provided',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    // Generate the DID
    final did = getDid(
      verificationMethods: verificationMethods,
      relationships: relationships,
      serviceEndpoints: serviceEndpoints,
    );

    final rels = relationships ?? {};
    final authIdx = rels[VerificationRelationship.authentication] ?? [];
    final kaIdx = rels[VerificationRelationship.keyAgreement] ?? [];
    final amIdx = rels[VerificationRelationship.assertionMethod] ?? [];
    final ciIdx = rels[VerificationRelationship.capabilityInvocation] ?? [];
    final cdIdx = rels[VerificationRelationship.capabilityDelegation] ?? [];

    // did:peer:0 is for a single key used only for authentication
    final isDid0 = verificationMethods.length == 1 &&
        authIdx.length == 1 &&
        authIdx.first == 0 &&
        kaIdx.isEmpty &&
        amIdx.isEmpty &&
        ciIdx.isEmpty &&
        cdIdx.isEmpty &&
        (serviceEndpoints == null || serviceEndpoints.isEmpty);

    if (isDid0) {
      final key = verificationMethods[0];
      final verificationMethod = VerificationMethodMultibase(
        id: did,
        controller: did,
        type: 'Multikey',
        publicKeyMultibase: toMultiBase(
          toMultikey(key.bytes, key.type),
        ),
      );

      final context = [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1'
      ];

      return DidDocument.create(
        context: Context.fromJson(context),
        id: did,
        verificationMethod: [verificationMethod],
        authentication: [did],
        assertionMethod: [did],
        capabilityInvocation: [did],
        capabilityDelegation: [did],
      );
    }

    // For did:peer:2, build document with proper key separation
    return _resolveDidPeer2(did);
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
