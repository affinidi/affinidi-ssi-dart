import 'dart:convert';
import 'dart:typed_data';

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';
import '../types.dart';
import '../util/json_util.dart';
import 'public_key_utils.dart';

class DidDocument implements JsonObject {
  List<String> context;
  late String id;
  List<String> alsoKnownAs;
  List<String> controller;
  List<VerificationMethod> verificationMethod;
  List<dynamic> authentication;
  List<dynamic> assertionMethod;
  List<dynamic> keyAgreement;
  List<dynamic> capabilityInvocation;
  List<dynamic> capabilityDelegation;
  List<ServiceEndpoint> service;

  DidDocument({
    context,
    required this.id,
    alsoKnownAs,
    controller,
    verificationMethod,
    authentication,
    keyAgreement,
    service,
    assertionMethod,
    capabilityDelegation,
    capabilityInvocation,
  })  : context = context ?? [],
        alsoKnownAs = alsoKnownAs ?? [],
        controller = controller ?? [],
        verificationMethod = verificationMethod ?? [],
        authentication = authentication ?? [],
        keyAgreement = keyAgreement ?? [],
        service = service ?? [],
        assertionMethod = assertionMethod ?? [],
        capabilityDelegation = capabilityDelegation ?? [],
        capabilityInvocation = capabilityInvocation ?? [];

  DidDocument.fromJson(dynamic jsonObject)
      : context = [],
        alsoKnownAs = [],
        controller = [],
        verificationMethod = [],
        authentication = [],
        keyAgreement = [],
        service = [],
        assertionMethod = [],
        capabilityDelegation = [],
        capabilityInvocation = [] {
    final document = jsonToMap(jsonObject);
    if (document.containsKey('@context')) {
      context = document['@context'].cast<String>();
    } else {
      context = extractStringOrSet(document, "context");
    }

    if (document.containsKey('id')) {
      id = document['id'];
    } else {
      throw FormatException('id property needed in did document');
    }
    
    if (document.containsKey('alsoKnownAs')) {
      alsoKnownAs = document['alsoKnownAs'].cast<String>();
    }

    if (document.containsKey('verificationMethod')) {
      List tmp = document['verificationMethod'];
      if (tmp.isNotEmpty) {
        verificationMethod = [];
        for (final v in tmp) {
          verificationMethod.add(VerificationMethod.fromJson(v));
        }
      }
    }

    if (document.containsKey('authentication')) {
      List tmp = document['authentication'];
      if (tmp.isNotEmpty) {
        authentication = [];
        for (final v in tmp) {
          if (v is String) {
            authentication.add(v);
          } else if (v is Map<String, dynamic>) {
            authentication.add(VerificationMethod.fromJson(v));
          } else {
            throw FormatException('unknown Datatype');
          }
        }
      }
    }

    if (document.containsKey('keyAgreement')) {
      List tmp = document['keyAgreement'];
      if (tmp.isNotEmpty) {
        keyAgreement = [];
        for (final v in tmp) {
          if (v is String) {
            keyAgreement.add(v);
          } else if (v is Map<String, dynamic>) {
            keyAgreement.add(VerificationMethod.fromJson(v));
          } else {
            throw FormatException('unknown Datatype');
          }
        }
      }
    }

    if (document.containsKey('assertionMethod')) {
      List tmp = document['assertionMethod'];
      if (tmp.isNotEmpty) {
        assertionMethod = [];
        for (final v in tmp) {
          if (v is String) {
            assertionMethod.add(v);
          } else if (v is Map<String, dynamic>) {
            assertionMethod.add(VerificationMethod.fromJson(v));
          } else {
            throw FormatException('unknown Datatype');
          }
        }
      }
    }

    if (document.containsKey('capabilityInvocation')) {
      List tmp = document['capabilityInvocation'];
      if (tmp.isNotEmpty) {
        capabilityInvocation = [];
        for (final v in tmp) {
          if (v is String) {
            capabilityInvocation.add(v);
          } else if (v is Map<String, dynamic>) {
            capabilityInvocation.add(VerificationMethod.fromJson(v));
          } else {
            throw FormatException('unknown Datatype');
          }
        }
      }
    }

    if (document.containsKey('capabilityDelegation')) {
      List tmp = document['capabilityDelegation'];
      if (tmp.isNotEmpty) {
        capabilityDelegation = [];
        for (final v in tmp) {
          if (v is String) {
            capabilityDelegation.add(v);
          } else if (v is Map<String, dynamic>) {
            capabilityDelegation.add(VerificationMethod.fromJson(v));
          } else {
            throw FormatException('unknown Datatype');
          }
        }
      }
    }

    if (document.containsKey('service')) {
      List tmp = document['service'];
      if (tmp.isNotEmpty) {
        service = [];
        for (final v in tmp) {
          service.add(ServiceEndpoint.fromJson(v));
        }
      }
    }
  }

  /// Resolve all keys given by their ids to their VerificationMethod from verification method section
  DidDocument resolveKeyIds() {
    if (verificationMethod.isEmpty) {
      return this;
    }
    final newDdo = DidDocument(
        id: id,
        context: context,
        controller: controller,
        alsoKnownAs: alsoKnownAs,
        service: service,
        verificationMethod: verificationMethod);
    Map<String, VerificationMethod> veriMap = {};
    for (final v in verificationMethod) {
      veriMap[v.id] = v;
      if (v.id.contains('#')) {
        final s = v.id.split('#');
        if (s.length == 2) {
          veriMap[s[1]] = v;
          veriMap['#${s[1]}'] = v;
        }
      }
    }
    if (assertionMethod.isNotEmpty) {
      newDdo.assertionMethod = _resolveIds(veriMap, assertionMethod);
    }
    if (keyAgreement.isNotEmpty) {
      newDdo.keyAgreement = _resolveIds(veriMap, keyAgreement);
    }
    if (authentication.isNotEmpty) {
      newDdo.authentication = _resolveIds(veriMap, authentication);
    }
    if (capabilityInvocation.isNotEmpty) {
      newDdo.capabilityInvocation = _resolveIds(veriMap, capabilityInvocation);
    }
    if (capabilityDelegation.isNotEmpty) {
      newDdo.capabilityDelegation = _resolveIds(veriMap, capabilityDelegation);
    }
    return newDdo;
  }

  List _resolveIds(Map<String, VerificationMethod> veriMap, List old) {
    List newList = [];
    for (final entry in old) {
      if (entry is VerificationMethod) {
        newList.add(entry);
      } else if (entry is String) {
        if (veriMap.containsKey(entry)) newList.add(veriMap[entry]);
      } else {
        throw SsiException(
          message: 'Element $entry has unsupported Datatype ${entry.runtimeType}',
          code: SsiExceptionType.invalidDidDocument.code,
        );
      }
    }
    return newList;
  }

  /// If keys are given as multibase-keys convert to Json web keys (this format is widely used in this package)
  // DidDocument convertAllKeysToJwk() {
  //   final newDdo = DidDocument(
  //       id: id,
  //       context: context,
  //       controller: controller,
  //       alsoKnownAs: alsoKnownAs,
  //       service: service);

  //   if (verificationMethod != null && verificationMethod.isNotEmpty) {
  //     List<VerificationMethod> newVm = [];
  //     for (final entry in verificationMethod) {
  //       newVm.add(entry.toPublicKeyJwk());
  //     }
  //     newDdo.verificationMethod = newVm;
  //   }
  //   if (assertionMethod != null && assertionMethod.isNotEmpty) {
  //     newDdo.assertionMethod = _convertKeys(assertionMethod);
  //   }
  //   if (keyAgreement != null && keyAgreement.isNotEmpty) {
  //     newDdo.keyAgreement = _convertKeys(keyAgreement);
  //   }
  //   if (authentication != null && authentication.isNotEmpty) {
  //     newDdo.authentication = _convertKeys(authentication);
  //   }
  //   if (capabilityInvocation != null && capabilityInvocation.isNotEmpty) {
  //     newDdo.capabilityInvocation = _convertKeys(capabilityInvocation);
  //   }
  //   if (capabilityDelegation != null && capabilityDelegation.isNotEmpty) {
  //     newDdo.capabilityDelegation = _convertKeys(capabilityDelegation);
  //   }
  //   return newDdo;
  // }

  // List _convertKeys(List old) {
  //   List newList = [];
  //   for (final entry in old) {
  //     if (entry is VerificationMethod) {
  //       newList.add(entry.toPublicKeyJwk());
  //     } else {
  //       newList.add(entry);
  //     }
  //   }
  //   return newList;
  // }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    if (context.isNotEmpty) jsonObject['@context'] = context;
    if (alsoKnownAs.isNotEmpty) jsonObject['alsoKnownAs'] = alsoKnownAs;
    if (controller.isNotEmpty) jsonObject['controller'] = controller;
    if (verificationMethod.isNotEmpty) {
      List tmp = [];
      for (final v in verificationMethod) {
        tmp.add(v.toJson());
      }
      jsonObject['verificationMethod'] = tmp;
    }

    if (authentication.isNotEmpty) {
      List tmp = [];
      for (final v in authentication) {
        if (v is VerificationMethod) {
          tmp.add(v.toJson());
        } else if (v is String) {
          tmp.add(v);
        } else {
          throw FormatException('unknown Datatype');
        }
      }
      jsonObject['authentication'] = tmp;
    }

    if (capabilityDelegation.isNotEmpty) {
      List tmp = [];
      for (final v in capabilityDelegation) {
        if (v is VerificationMethod) {
          tmp.add(v.toJson());
        } else if (v is String) {
          tmp.add(v);
        } else {
          throw FormatException('unknown Datatype');
        }
      }
      jsonObject['capabilityDelegation'] = tmp;
    }

    if (capabilityInvocation.isNotEmpty) {
      List tmp = [];
      for (final v in capabilityInvocation) {
        if (v is VerificationMethod) {
          tmp.add(v.toJson());
        } else if (v is String) {
          tmp.add(v);
        } else {
          throw FormatException('unknown Datatype');
        }
      }
      jsonObject['capabilityInvocation'] = tmp;
    }

    if (keyAgreement.isNotEmpty) {
      List tmp = [];
      for (final v in keyAgreement) {
        if (v is VerificationMethod) {
          tmp.add(v.toJson());
        } else if (v is String) {
          tmp.add(v);
        } else {
          throw FormatException('unknown Datatype');
        }
      }
      jsonObject['keyAgreement'] = tmp;
    }

    if (assertionMethod.isNotEmpty) {
      List tmp = [];
      for (final v in assertionMethod) {
        if (v is VerificationMethod) {
          tmp.add(v.toJson());
        } else if (v is String) {
          tmp.add(v);
        } else {
          throw FormatException('unknown Datatype');
        }
      }
      jsonObject['assertionMethod'] = tmp;
    }

    if (service.isNotEmpty) {
      List tmp = [];
      for (final v in service) {
        tmp.add(v.toJson());
      }
      jsonObject['service'] = tmp;
    }

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

// TODO(FTL-20741) define better structure
class Jwk {
  late final Map<String, String> doc;

  Jwk.fromJson(dynamic input) {
    final map = jsonToMap(input);

    try {
      doc = map.map((key, value) => MapEntry(key, value as String));
    } catch (error, stackTrace) {
      Error.throwWithStackTrace(
        SsiException(
          message: 'Invalid JWK',
          code: SsiExceptionType.invalidDidDocument.code,
          originalMessage: error.toString(),
        ),
        stackTrace,
      );
    }
  }

  Map<String, String> toJson() {
    return doc;
  }
}

abstract class VerificationMethod implements JsonObject {
  final String id;
  final String controller;
  final String type;

  VerificationMethod({
    required this.id,
    required this.controller,
    required this.type,
  });

  /// Returns the public key as a JWK
  Jwk asJwk();

  /// Returns the public key as a raw multikey
  Uint8List asMultiKey();

  /// Returns the public key as a multibase encoded multikey
  String asMultiBase() {
    return toMultiBase(asMultiKey());
  }

  factory VerificationMethod.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final id = getMandatoryString(json, 'id');
    final type = getMandatoryString(json, 'type');
    final controller = getMandatoryString(json, 'controller');

    final publicKeyJwk = json['publicKeyJwk'];
    final publicKeyMultibase = json['publicKeyMultibase'];
    // NOTE: do we need to cover publicKeyBase58?

    if (publicKeyJwk != null) {
      final jwk = Jwk.fromJson(publicKeyJwk);
      return VerificationMethodJwk(
        id: id,
        type: type,
        controller: controller,
        publicKeyJwk: jwk,
      );
    } else if (publicKeyMultibase != null) {
      return VerificationMethodMultibase(
        id: id,
        type: type,
        controller: controller,
        publicKeyMultibase: publicKeyMultibase,
      );
    }

    throw SsiException(
      message: 'Verification Method must have an entry for a public key',
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }

  /// Convert a multibase key to Json web Key
  // VerificationMethod toPublicKeyJwk() {
  //   if (publicKeyMultibase != null) {
  //     final pkJwk = multibaseKeyToJwk(publicKeyMultibase!);
  //     // TIMTAM#4 - if the id is relative, prepend the controller
  //     //            prepended controller, so that the key is fully qualified
  //     pkJwk['kid'] = (id.startsWith('#') ? controller + id : id);
  //     return VerificationMethod(
  //         id: id,
  //         controller: controller,
  //         type: 'JsonWebKey2020',
  //         publicKeyJwk: pkJwk);
  //   } else if (publicKeyJwk != null) {
  //     // TIMTAM#5 - If the kid is missing in the provided
  //     // JsonWebKey2020, need to put it in there
  //     publicKeyJwk!['kid'] = (id.startsWith('#') ? controller + id : id);
  //     return this;
  //   } else {
  //         throw SsiException(
  //    message: 'Cant find key in this Verification Method',
  //    code: SsiExceptionType.invalidDidDocument.code,
  //  );
  //   }
  // }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['controller'] = controller;
    jsonObject['type'] = type;

    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class VerificationMethodJwk extends VerificationMethod {
  final Jwk publicKeyJwk;

  VerificationMethodJwk({
    required super.id,
    required super.controller,
    required super.type,
    required this.publicKeyJwk,
  });

  @override
  Jwk asJwk() {
    return publicKeyJwk;
  }

  @override
  Uint8List asMultiKey() {
    return jwkToMultiKey(publicKeyJwk.toJson());
  }

  @override
  Map<String, dynamic> toJson() {
    final jsonObject = super.toJson();

    jsonObject['publicKeyJwk'] = publicKeyJwk.toJson();

    return jsonObject;
  }
}

class VerificationMethodMultibase extends VerificationMethod {
  late final Uint8List publicKeyMultikey;
  final String publicKeyMultibase;

  VerificationMethodMultibase({
    required super.id,
    required super.controller,
    required super.type,
    required this.publicKeyMultibase,
  }) : publicKeyMultikey = multiBaseToUint8List(publicKeyMultibase);

  @override
  Jwk asJwk() {
    return Jwk.fromJson(multiKeyToJwk(publicKeyMultikey));
  }

  @override
  Uint8List asMultiKey() {
    return publicKeyMultikey;
  }

  @override
  Map<String, dynamic> toJson() {
    final jsonObject = super.toJson();

    jsonObject['publicKeyMultibase'] = publicKeyMultibase;

    return jsonObject;
  }
}

class ServiceEndpoint implements JsonObject {
  late String id;
  late String type;
  late dynamic serviceEndpoint;
  late dynamic accept;

  ServiceEndpoint({required this.id, required this.type, required this.serviceEndpoint});

  ServiceEndpoint.fromJson(dynamic jsonObject) {
    final se = jsonToMap(jsonObject);
    if (se.containsKey('id')) {
      id = se['id'];
    } else {
      throw FormatException('id property is needed in serviceEndpoint');
    }
    if (se.containsKey('type')) {
      type = se['type'];
    } else {
      throw FormatException('format property is needed in serviceEndpoint');
    }
    if (se.containsKey('serviceEndpoint')) {
      serviceEndpoint = se['serviceEndpoint'];
    } else {
      throw FormatException('serviceEndpoint property is needed in serviceEndpoint');
    }
    if (se.containsKey('accept')) {
      accept = se['accept'];
    }
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['type'] = type;
    jsonObject['serviceEndpoint'] = serviceEndpoint;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

List<String> extractStringOrSet(Map<String, dynamic> document, String field) {
  final jsonValue = document[field];

  switch (jsonValue) {
    case null:
      return [];

    case String str:
      return [str];

    case List<String> strList:
      return strList;

    default:
      throw SsiException(
        message: '$field must be a String or a List',
        code: SsiExceptionType.invalidDidDocument.code,
      );
  }
}
