import 'dart:convert';

import '../credentials/exceptions/ssi_exception.dart';
import '../credentials/exceptions/ssi_exception_type.dart';
import '../types.dart';

Map<String, dynamic> credentialToMap(dynamic credential) {
  if (credential is String) {
    return jsonDecode(credential);
  } else if (credential is Map<String, dynamic>) {
    return credential;
  } else if (credential is Map<dynamic, dynamic>) {
    return credential.map((key, value) => MapEntry(key as String, value));
  } else {
    throw SsiException(
      message:
          'Unknown datatype ${credential.runtimeType} for $credential. Only String or Map<String, dynamic> accepted',
      code: SsiExceptionType.invalidDidDocument.code,
    );
  }
}

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
    var document = credentialToMap(jsonObject);
    if (document.containsKey('@context')) {
      context = document['@context'].cast<String>();
    }
    if (document.containsKey('id')) {
      id = document['id'];
    } else {
      throw FormatException('id property needed in did document');
    }
    if (document.containsKey('alsoKnownAs')) {
      alsoKnownAs = document['alsoKnownAs'].cast<String>();
    }

    context = extractStringOrSet(document, "context");

    if (document.containsKey('verificationMethod')) {
      List tmp = document['verificationMethod'];
      if (tmp.isNotEmpty) {
        verificationMethod = [];
        for (var v in tmp) {
          verificationMethod.add(VerificationMethod.fromJson(v));
        }
      }
    }

    if (document.containsKey('authentication')) {
      List tmp = document['authentication'];
      if (tmp.isNotEmpty) {
        authentication = [];
        for (var v in tmp) {
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
        for (var v in tmp) {
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
        for (var v in tmp) {
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
        for (var v in tmp) {
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
        for (var v in tmp) {
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
        for (var v in tmp) {
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
    var newDdo = DidDocument(
        id: id,
        context: context,
        controller: controller,
        alsoKnownAs: alsoKnownAs,
        service: service,
        verificationMethod: verificationMethod);
    Map<String, VerificationMethod> veriMap = {};
    for (var v in verificationMethod) {
      veriMap[v.id] = v;
      if (v.id.contains('#')) {
        var s = v.id.split('#');
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
    for (var entry in old) {
      if (entry is VerificationMethod) {
        newList.add(entry);
      } else if (entry is String) {
        if (veriMap.containsKey(entry)) newList.add(veriMap[entry]);
      } else {
        throw SsiException(
          message:
              'Element $entry has unsupported Datatype ${entry.runtimeType}',
          code: SsiExceptionType.invalidDidDocument.code,
        );
      }
    }
    return newList;
  }

  /// If keys are given as multibase-keys convert to Json web keys (this format is widely used in this package)
  // DidDocument convertAllKeysToJwk() {
  //   var newDdo = DidDocument(
  //       id: id,
  //       context: context,
  //       controller: controller,
  //       alsoKnownAs: alsoKnownAs,
  //       service: service);

  //   if (verificationMethod != null && verificationMethod.isNotEmpty) {
  //     List<VerificationMethod> newVm = [];
  //     for (var entry in verificationMethod) {
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
  //   for (var entry in old) {
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
    if (alsoKnownAs.isNotEmpty) jsonObject['alsoKnownAs'] = alsoKnownAs;
    if (controller.isNotEmpty) jsonObject['controller'] = controller;
    if (verificationMethod.isNotEmpty) {
      List tmp = [];
      for (var v in verificationMethod) {
        tmp.add(v.toJson());
      }
      jsonObject['verificationMethod'] = tmp;
    }

    if (authentication.isNotEmpty) {
      List tmp = [];
      for (var v in authentication) {
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
      for (var v in capabilityDelegation) {
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
      for (var v in capabilityInvocation) {
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
      for (var v in keyAgreement) {
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
      for (var v in assertionMethod) {
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
      for (var v in service) {
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

class VerificationMethod implements JsonObject {
  late String id;
  late String controller;
  late String type;
  Map<String, dynamic>? publicKeyJwk;
  String? publicKeyMultibase;

  VerificationMethod(
      {required this.id,
      required this.controller,
      required this.type,
      this.publicKeyJwk,
      this.publicKeyMultibase}) {
    if (publicKeyJwk == null && publicKeyMultibase == null) {
      throw SsiException(
        message: 'Verification Method must have an entry for a public key',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
  }

  VerificationMethod.fromJson(dynamic jsonObject) {
    var method = credentialToMap(jsonObject);
    if (method.containsKey('id')) {
      id = method['id'];
    } else {
      throw FormatException('id property is needed in Verification Method');
    }
    if (method.containsKey('type')) {
      type = method['type'];
    } else {
      throw FormatException('type property is needed in Verification Method');
    }
    if (method.containsKey('controller')) {
      controller = method['controller'];
    } else {
      throw FormatException(
          'controller property is needed in Verification Method');
    }
    publicKeyJwk = method['publicKeyJwk'];
    publicKeyMultibase = method['publicKeyMultibase'];

    if (publicKeyJwk == null && publicKeyMultibase == null) {
      throw SsiException(
        message: 'Verification Method must have an entry for a public key',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }
  }

  /// Convert a multibase key to Json web Key
  // VerificationMethod toPublicKeyJwk() {
  //   if (publicKeyMultibase != null) {
  //     var pkJwk = multibaseKeyToJwk(publicKeyMultibase!);
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
    if (publicKeyMultibase != null) {
      jsonObject['publicKeyMultibase'] = publicKeyMultibase;
    }
    if (publicKeyJwk != null) jsonObject['publicKeyJwk'] = publicKeyJwk;
    return jsonObject;
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

class ServiceEndpoint implements JsonObject {
  late String id;
  late String type;
  late dynamic serviceEndpoint;
  late dynamic accept;

  ServiceEndpoint(
      {required this.id, required this.type, required this.serviceEndpoint});

  ServiceEndpoint.fromJson(dynamic jsonObject) {
    var se = credentialToMap(jsonObject);
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
      throw FormatException(
          'serviceEndpoint property is needed in serviceEndpoint');
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
