import 'dart:convert';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../json_ld/context.dart';
import '../../types.dart';
import '../../util/json_util.dart';
import 'service_endpoint.dart';
import 'verification_method.dart';

/// Represents a DID Document as defined by the W3C DID specification.
class DidDocument implements JsonObject {
  /// The JSON-LD context of the DID document.
  Context context;

  /// The DID that the DID document is about.
  late String id;

  /// Alternative identifiers for the DID subject.
  List<String> alsoKnownAs;

  /// The DIDs of entities that have the authority to make changes to the DID document.
  List<String> controller;

  /// The verification methods of the DID document.
  List<EmbeddedVerificationMethod> verificationMethod;

  /// Authentication verification methods.
  List<VerificationMethod> authentication;

  /// Assertion method verification methods.
  List<VerificationMethod> assertionMethod;

  /// Key agreement verification methods.
  List<VerificationMethod> keyAgreement;

  /// Capability invocation verification methods.
  List<VerificationMethod> capabilityInvocation;

  /// Capability delegation verification methods.
  List<VerificationMethod> capabilityDelegation;

  /// Services offered by the DID subject.
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

  /// Creates a new DID document with the specified properties.
  ///
  /// [id] The DID that the DID document is about.
  factory DidDocument.create({
    Context? context,
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
    final vmMap = <String, EmbeddedVerificationMethod>{};
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
      context: context ?? Context.fromJson(''),
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

  /// Converts a list of service endpoints to the proper format.
  ///
  /// [input] The input to convert.
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

  /// Converts a list of verification methods to the proper format.
  ///
  /// [input] The input to convert.
  /// [verificationMethodMap] The map of verification methods.
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
  /// Creates a [DidDocument] from JSON data.
  ///
  /// [jsonObject] The JSON data to create the DID document from.
  DidDocument.fromJson(dynamic jsonObject)
      : context = Context.fromJson(''),
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

    // Handle missing @context field - provide default W3C DID context
    final contextValue = document['@context'];
    if (contextValue != null) {
      context = Context.fromJson(contextValue);
    } else {
      // Default to W3C DID context when @context is missing
      context = Context.fromJson('https://www.w3.org/ns/did/v1');
    }

    if (document.containsKey('id')) {
      id = document['id'];
    } else {
      throw const FormatException('id property needed in did document');
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

  /// Converts a list of items to a JSON list.
  ///
  /// [items] The items to convert.
  List _toJsonList(List items) {
    if (items.isEmpty) return [];
    return items.map((e) => e.toJson()).toList();
  }

  @override
  Map<String, dynamic> toJson() {
    var jsonObject = <String, dynamic>{};
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

/// Represents a JSON Web Key (JWK) used in DID documents.
class Jwk {
  /// The JWK document as a map.
  late final Map<String, String> doc;

  /// Creates a [Jwk] from JSON data.
  ///
  /// [input] The JSON data to create the JWK from.
  Jwk.fromJson(dynamic input) {
    final map = jsonToMap(input);

    try {
      doc = Map<String, String>.from(map);
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

  /// Converts the JWK to JSON.
  Map<String, String> toJson() {
    return doc;
  }
}
