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
import 'did_manager/verification_relationship.dart';
import 'public_key_utils.dart';

const _serviceKeyAbbreviations = {
  'type': 't',
  'serviceEndpoint': 's',
  'routingKeys': 'r',
  'accept': 'a',
};

const _serviceTypeAbbreviations = {
  'DIDCommMessaging': 'dm',
};

final _serviceKeyDeabbreviations =
    _serviceKeyAbbreviations.map((k, v) => MapEntry(v, k));
final _serviceTypeDeabbreviations =
    _serviceTypeAbbreviations.map((k, v) => MapEntry(v, k));

dynamic _abbreviateService(dynamic json) {
  if (json is Map<String, dynamic>) {
    final newMap = <String, dynamic>{};
    for (final entry in json.entries) {
      var key = entry.key;
      var value = entry.value;

      final dynamic abbreviatedValue;
      if (key == 'type' &&
          value is String &&
          _serviceTypeAbbreviations.containsKey(value)) {
        abbreviatedValue = _serviceTypeAbbreviations[value]!;
      } else {
        abbreviatedValue = _abbreviateService(value);
      }

      final abbreviatedKey = _serviceKeyAbbreviations[key] ?? key;

      newMap[abbreviatedKey] = abbreviatedValue;
    }
    return newMap;
  } else if (json is List) {
    return json.map(_abbreviateService).toList();
  }
  return json;
}

dynamic _deabbreviateService(dynamic json) {
  if (json is Map<String, dynamic>) {
    final newMap = <String, dynamic>{};
    for (final entry in json.entries) {
      var key = entry.key;
      var value = entry.value;

      final deabbreviatedKey = _serviceKeyDeabbreviations[key] ?? key;

      final dynamic deabbreviatedValue;
      if (deabbreviatedKey == 'type' &&
          value is String &&
          _serviceTypeDeabbreviations.containsKey(value)) {
        deabbreviatedValue = _serviceTypeDeabbreviations[value]!;
      } else {
        deabbreviatedValue = _deabbreviateService(value);
      }

      newMap[deabbreviatedKey] = deabbreviatedValue;
    }
    return newMap;
  } else if (json is List) {
    return json.map(_deabbreviateService).toList();
  }
  return json;
}

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

  const multikeyContext = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/multikey/v1'
  ];

  var keyPart = did.substring(11);

  // ed25519
  if (keyPart.startsWith('6Mk')) {
    return _buildEDDoc(multikeyContext, did, keyPart);
  }

  final forSigning = keyPart.startsWith('Dn') || // p256
      keyPart.startsWith('Q3s') || // secp256k1
      keyPart.startsWith('82') || // p384
      keyPart.startsWith('2J9'); // p521

  // x25519
  final forKeyAgreement = keyPart.startsWith('6LS');

  if (forSigning || forKeyAgreement) {
    return _buildSimpleDoc(
      multikeyContext,
      did,
      keyPart,
      forSigning: forSigning,
      forKeyAgreement: forKeyAgreement,
    );
  }

  throw SsiException(
    message: 'Unsupported key type',
    code: SsiExceptionType.invalidKeyType.code,
  );
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
        final deabbreviatedJson = _deabbreviateService(decodedJson);
        final originalMap = jsonToMap(deabbreviatedJson);

        var serviceId = originalMap['id'];
        if (serviceId == null) {
          if (unnamedServiceIndex == 0) {
            serviceId = '#service';
          } else {
            serviceId = '#service-$unnamedServiceIndex';
          }
          unnamedServiceIndex++;
          originalMap['id'] = serviceId;
        }

        services.add(ServiceEndpoint.fromJson(originalMap));
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
  final x25519PubKey =
      ed25519PublicToX25519Public(base58Bitcoin.decode(keyPart).sublist(2));
  final x25519PubKeyMultiBase = toMultiBase(
    toMultikey(x25519PubKey, KeyType.x25519),
  );

  var verificationKeyId = '$id#z$keyPart';
  var agreementKeyId = '$id#$x25519PubKeyMultiBase';

  final verificationMethod = VerificationMethodMultibase(
    id: verificationKeyId,
    controller: id,
    type: 'Multikey',
    publicKeyMultibase: 'z$keyPart',
  );

  final keyAgreementMethod = VerificationMethodMultibase(
    id: agreementKeyId,
    controller: id,
    type: 'Multikey',
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

/// Builds a simple DID Document for a single key.
DidDocument _buildSimpleDoc(
  List<String> context,
  String id,
  String keyPart, {
  bool forSigning = false,
  bool forKeyAgreement = false,
}) {
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
    assertionMethod: forSigning ? [verificationKeyId] : null,
    authentication: forSigning ? [verificationKeyId] : null,
    capabilityDelegation: forSigning ? [verificationKeyId] : null,
    capabilityInvocation: forSigning ? [verificationKeyId] : null,
    keyAgreement: forKeyAgreement ? [verificationKeyId] : null,
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
      final serviceJson = service.toJson();
      final abbreviatedJson = _abbreviateService(serviceJson);

      final jsonToEncode = json.encode(abbreviatedJson);
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

    // did:peer:0 is for a single key (equivalent to did:key).
    final isDid0 = verificationMethods.length == 1 &&
        (serviceEndpoints == null || serviceEndpoints.isEmpty);

    if (isDid0) {
      final signingKey = verificationMethods[0];
      final multibase = toMultiBase(
        toMultikey(signingKey.bytes, signingKey.type),
      );
      return '${_didTypePrefixes[DidPeerType.peer0]}$multibase';
    }

    final indexToPurpose = <int, VerificationRelationship>{};
    for (final entry in rels.entries) {
      for (final index in entry.value) {
        indexToPurpose[index] = entry.key;
      }
    }

    Numalgo2Prefix getPrefixForRelationship(VerificationRelationship rel) {
      return switch (rel) {
        VerificationRelationship.authentication =>
          Numalgo2Prefix.authentication,
        VerificationRelationship.keyAgreement => Numalgo2Prefix.keyAgreement,
        VerificationRelationship.assertionMethod => Numalgo2Prefix.assertion,
        VerificationRelationship.capabilityInvocation =>
          Numalgo2Prefix.capabilityInvocation,
        VerificationRelationship.capabilityDelegation =>
          Numalgo2Prefix.capabilityDelegation,
      };
    }

    var keyStr = '';
    for (var i = 0; i < verificationMethods.length; i++) {
      final purpose = indexToPurpose[i];
      if (purpose != null) {
        final prefix = getPrefixForRelationship(purpose);
        final keyMultibase = toMultiBase(toMultikey(
            verificationMethods[i].bytes, verificationMethods[i].type));
        keyStr += '.${prefix.value}$keyMultibase';
      }
    }

    final serviceStr = _buildServiceEncoded(serviceEndpoints);

    return '${_didTypePrefixes[DidPeerType.peer2]}$keyStr$serviceStr';
  }

  /// Generates a DID Document from a pre-defined state.
  ///
  /// This method is used when the verification method IDs are already known
  /// and should be preserved, which is the case for `did:peer:2` documents
  /// managed by a controller.
  static DidDocument generateDocument({
    required String did,
    required List<String> verificationMethodIds,
    required List<PublicKey> publicKeys,
    required Map<VerificationRelationship, List<String>> relationships,
    required List<ServiceEndpoint> serviceEndpoints,
  }) {
    final context = [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1'
    ];

    final vms = <EmbeddedVerificationMethod>[];
    for (var i = 0; i < verificationMethodIds.length; i++) {
      final vmId = verificationMethodIds[i];
      final pubKey = publicKeys[i];
      vms.add(VerificationMethodMultibase(
        id: vmId,
        controller: did,
        type: 'Multikey',
        publicKeyMultibase: toMultiBase(toMultikey(pubKey.bytes, pubKey.type)),
      ));
    }

    return DidDocument.create(
      context: Context.fromJson(context),
      id: did,
      verificationMethod: vms,
      authentication:
          relationships[VerificationRelationship.authentication] ?? [],
      keyAgreement: relationships[VerificationRelationship.keyAgreement] ?? [],
      assertionMethod:
          relationships[VerificationRelationship.assertionMethod] ?? [],
      capabilityInvocation:
          relationships[VerificationRelationship.capabilityInvocation] ?? [],
      capabilityDelegation:
          relationships[VerificationRelationship.capabilityDelegation] ?? [],
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

    if (DidPeer.determineType(did) == DidPeerType.peer0) {
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
