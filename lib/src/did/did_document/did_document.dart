import 'dart:convert';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../json_ld/context.dart';
import '../../types.dart';
import '../../util/json_util.dart';
import 'service_endpoint.dart';
import 'verification_method.dart';

class DidDocument implements JsonObject {
  Context context;
  late String id;
  List<String> alsoKnownAs;
  List<String> controller;
  List<EmbeddedVerificationMethod> verificationMethod;
  List<VerificationMethod> authentication;
  List<VerificationMethod> assertionMethod;
  List<VerificationMethod> keyAgreement;
  List<VerificationMethod> capabilityInvocation;
  List<VerificationMethod> capabilityDelegation;
  List<ServiceEndpoint> service;

  DidDocument._({
    required this.context,
    required this.id,
    required this.alsoKnownAs,
    required this.controller,
    required this.verificationMethod,
    required this.authentication,
    required this.keyAgreement,
    required this.service,
    required this.assertionMethod,
    required this.capabilityDelegation,
    required this.capabilityInvocation,
  });

  factory DidDocument.create({
    context,
    required String id,
    alsoKnownAs,
    controller,
    verificationMethod,
    authentication,
    keyAgreement,
    service,
    assertionMethod,
    capabilityDelegation,
    capabilityInvocation,
  }) {
    final List<VerificationMethod> methods = verificationMethod ?? [];
    final Map<String, EmbeddedVerificationMethod> vmMap = {};
    for (final vm in methods) {
      if (vm is EmbeddedVerificationMethod) {
        vmMap[vm.id] = vm;
        if (vm.id.contains('#')) {
          final fragment = vm.id.split('#').last;
          vmMap['#$fragment'] = vm;
          vmMap[fragment] = vm;
        }
      }
    }

    return DidDocument._(
      context: context ?? Context.fromJson(""),
      id: id,
      alsoKnownAs: alsoKnownAs ?? [],
      controller: controller ?? [],
      verificationMethod: verificationMethod ?? [],
      authentication: _convertToVerificationRelationship(authentication, vmMap),
      keyAgreement: _convertToVerificationRelationship(keyAgreement, vmMap),
      service: _convertToServiceEndpoint(service),
      assertionMethod:
          _convertToVerificationRelationship(assertionMethod, vmMap),
      capabilityDelegation:
          _convertToVerificationRelationship(capabilityDelegation, vmMap),
      capabilityInvocation:
          _convertToVerificationRelationship(capabilityInvocation, vmMap),
    );
  }
  static List<ServiceEndpoint> _convertToServiceEndpoint(dynamic input) {
    if (input == null) {
      return [];
    }
    if (input is List<ServiceEndpoint>) {
      return input;
    }
    if (input is List) {
      return input
          .map((item) =>
              item is ServiceEndpoint ? item : ServiceEndpoint.fromJson(item))
          .toList();
    }
    return [];
  }

  static List<VerificationMethod> _convertToVerificationRelationship(
    dynamic input,
    Map<String, EmbeddedVerificationMethod> verificationMethodMap,
  ) {
    if (input == null) {
      return [];
    }
    if (input is List<VerificationMethod>) {
      return input;
    }
    if (input is List) {
      return input
          .map(
            (item) => item is VerificationMethodRef
                ? item
                : VerificationMethod.fromJson(item, verificationMethodMap),
          )
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

    if (document.containsKey('controller')) {
      final controllerValue = document['controller'];
      if (controllerValue is String) {
        controller = [controllerValue];
      } else if (controllerValue is List) {
        controller = controllerValue.cast<String>();
      }
    }

    if (document.containsKey('alsoKnownAs')) {
      final alsoKnownAsValue = document['alsoKnownAs'];
      if (alsoKnownAsValue is String) {
        alsoKnownAs = [alsoKnownAsValue];
      } else if (alsoKnownAsValue is List) {
        alsoKnownAs = alsoKnownAsValue.cast<String>();
      }
    }

    final vmMap = <String, EmbeddedVerificationMethod>{};
    if (document.containsKey('verificationMethod')) {
      List tmp = document['verificationMethod'];
      if (tmp.isNotEmpty) {
        verificationMethod = [];
        for (final v in tmp) {
          var vm = EmbeddedVerificationMethod.fromJson(v);
          verificationMethod.add(vm);
          vmMap[vm.id] = vm;
          if (vm.id.contains('#')) {
            final fragment = vm.id.split('#').last;
            vmMap['#$fragment'] = vm;
            vmMap[fragment] = vm;
          }
        }
      }
    }

    if (document.containsKey('authentication')) {
      List tmp = document['authentication'];
      if (tmp.isNotEmpty) {
        authentication = [];
        for (final v in tmp) {
          authentication.add(VerificationMethod.fromJson(v, vmMap));
        }
      }
    }

    if (document.containsKey('keyAgreement')) {
      List tmp = document['keyAgreement'];
      if (tmp.isNotEmpty) {
        keyAgreement = [];
        for (final v in tmp) {
          keyAgreement.add(VerificationMethod.fromJson(v, vmMap));
        }
      }
    }

    if (document.containsKey('assertionMethod')) {
      List tmp = document['assertionMethod'];
      if (tmp.isNotEmpty) {
        assertionMethod = [];
        for (final v in tmp) {
          assertionMethod.add(VerificationMethod.fromJson(v, vmMap));
        }
      }
    }

    if (document.containsKey('capabilityInvocation')) {
      List tmp = document['capabilityInvocation'];
      if (tmp.isNotEmpty) {
        capabilityInvocation = [];
        for (final v in tmp) {
          capabilityInvocation.add(VerificationMethod.fromJson(v, vmMap));
        }
      }
    }

    if (document.containsKey('capabilityDelegation')) {
      List tmp = document['capabilityDelegation'];
      if (tmp.isNotEmpty) {
        capabilityDelegation = [];
        for (final v in tmp) {
          capabilityDelegation.add(VerificationMethod.fromJson(v, vmMap));
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

  List _toJsonList(List items) {
    if (items.isEmpty) return [];
    return items.map((e) => e.toJson()).toList();
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonObject = {};
    jsonObject['id'] = id;
    jsonObject['@context'] = context.toJson();
    if (alsoKnownAs.isNotEmpty) jsonObject['alsoKnownAs'] = alsoKnownAs;
    if (controller.isNotEmpty) jsonObject['controller'] = controller;
    final verificationMethodJson = _toJsonList(verificationMethod);
    if (verificationMethodJson.isNotEmpty) {
      jsonObject['verificationMethod'] = verificationMethodJson;
    }

    if (authentication.isNotEmpty) {
      jsonObject['authentication'] = _toJsonList(authentication);
    }

    if (capabilityDelegation.isNotEmpty) {
      jsonObject['capabilityDelegation'] = _toJsonList(capabilityDelegation);
    }

    if (capabilityInvocation.isNotEmpty) {
      jsonObject['capabilityInvocation'] = _toJsonList(capabilityInvocation);
    }

    if (keyAgreement.isNotEmpty) {
      jsonObject['keyAgreement'] = _toJsonList(keyAgreement);
    }

    if (assertionMethod.isNotEmpty) {
      jsonObject['assertionMethod'] = _toJsonList(assertionMethod);
    }

    if (service.isNotEmpty) {
      jsonObject['service'] = _toJsonList(service);
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
