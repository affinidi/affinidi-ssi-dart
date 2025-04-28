import 'dart:convert';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../json_ld/context.dart';
import '../../types.dart';
import '../../util/json_util.dart';
import 'service_endpoint.dart';
import 'verification_method.dart';
import 'verification_relationship.dart';

class DidDocument implements JsonObject {
  Context context;
  late String id;
  List<String> alsoKnownAs;
  List<String> controller;
  List<VerificationMethod> verificationMethod;
  List<VerificationRelationship> authentication;
  List<VerificationRelationship> assertionMethod;
  List<VerificationRelationship> keyAgreement;
  List<VerificationRelationship> capabilityInvocation;
  List<VerificationRelationship> capabilityDelegation;
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
  })  : context = context ?? Context.fromJson(""),
        alsoKnownAs = alsoKnownAs ?? [],
        controller = controller ?? [],
        verificationMethod = verificationMethod ?? [],
        authentication = _convertToVerificationRelationship(authentication),
        keyAgreement = _convertToVerificationRelationship(keyAgreement),
        service = _convertToServiceEndpoint(service),
        assertionMethod = _convertToVerificationRelationship(assertionMethod),
        capabilityDelegation =
            _convertToVerificationRelationship(capabilityDelegation),
        capabilityInvocation =
            _convertToVerificationRelationship(capabilityInvocation);

  static List<ServiceEndpoint> _convertToServiceEndpoint(dynamic input) {
    if (input == null) {
      return [];
    }
    if (input is List<ServiceEndpoint>) {
      return input;
    }
    if (input is List) {
      return input
          .map((item) => item is ServiceEndpoint
              ? item
              : ServiceEndpoint.fromJson(item))
          .toList();
    }
    return [];
  }

  static List<VerificationRelationship> _convertToVerificationRelationship(
      dynamic input) {
    if (input == null) {
      return [];
    }
    if (input is List<VerificationRelationship>) {
      return input;
    }
    if (input is List) {
      return input
          .map((item) => item is VerificationRelationship
              ? item
              : VerificationRelationship.fromJson(item))
          .toList();
    }
    return [];
  }

  // TODO: convert to factory method
  DidDocument.fromJson(dynamic jsonObject)
      : context = Context.fromJson(""),
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

    context = Context.fromJson(document['@context']);

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
          authentication.add(VerificationRelationship.fromJson(v));
        }
      }
    }

    if (document.containsKey('keyAgreement')) {
      List tmp = document['keyAgreement'];
      if (tmp.isNotEmpty) {
        keyAgreement = [];
        for (final v in tmp) {
          keyAgreement.add(VerificationRelationship.fromJson(v));
        }
      }
    }

    if (document.containsKey('assertionMethod')) {
      List tmp = document['assertionMethod'];
      if (tmp.isNotEmpty) {
        assertionMethod = [];
        for (final v in tmp) {
          assertionMethod.add(VerificationRelationship.fromJson(v));
        }
      }
    }

    if (document.containsKey('capabilityInvocation')) {
      List tmp = document['capabilityInvocation'];
      if (tmp.isNotEmpty) {
        capabilityInvocation = [];
        for (final v in tmp) {
          capabilityInvocation.add(VerificationRelationship.fromJson(v));
        }
      }
    }

    if (document.containsKey('capabilityDelegation')) {
      List tmp = document['capabilityDelegation'];
      if (tmp.isNotEmpty) {
        capabilityDelegation = [];
        for (final v in tmp) {
          capabilityDelegation.add(VerificationRelationship.fromJson(v));
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

  List<VerificationRelationship> _resolveIds(
      Map<String, VerificationMethod> veriMap,
      List<VerificationRelationship> old) {
    return old.map((entry) => entry.resolveWith(veriMap)).toList();
  }

  // TODO: Implement or remove this method
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
    jsonObject['@context'] = context.toJson();
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
        tmp.add(v.toJson());
      }
      jsonObject['authentication'] = tmp;
    }

    if (capabilityDelegation.isNotEmpty) {
      List tmp = [];
      for (final v in capabilityDelegation) {
        tmp.add(v.toJson());
      }
      jsonObject['capabilityDelegation'] = tmp;
    }

    if (capabilityInvocation.isNotEmpty) {
      List tmp = [];
      for (final v in capabilityInvocation) {
        tmp.add(v.toJson());
      }
      jsonObject['capabilityInvocation'] = tmp;
    }

    if (keyAgreement.isNotEmpty) {
      List tmp = [];
      for (final v in keyAgreement) {
        tmp.add(v.toJson());
      }
      jsonObject['keyAgreement'] = tmp;
    }

    if (assertionMethod.isNotEmpty) {
      List tmp = [];
      for (final v in assertionMethod) {
        tmp.add(v.toJson());
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
