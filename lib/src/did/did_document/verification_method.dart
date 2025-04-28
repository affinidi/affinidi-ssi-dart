import 'dart:convert';
import 'dart:typed_data';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../util/json_util.dart';
import '../public_key_utils.dart';
import 'did_document.dart';

sealed class VerificationMethod implements JsonObject {
  String get id;

  String get controller;

  String get type;

  Jwk asJwk();

  Uint8List asMultiKey();

  factory VerificationMethod.fromJson(dynamic value, Map<Uri, VerificationMethod> verificationMethod,) {
    if (value is String) {
      final verificationMethod = verificationMethod[Uri.parse(value)];
      return VerificationMethodRef(reference: Uri.parse(value), method: verificationMethod);
    } else if (value is Map<String, dynamic>) {
      return EmbeddedVerificationMethod.fromJson(value);
    } else if (value is VerificationMethod) {
      return value;
    } else if (value is VerificationMethodRef) {
      return value;
    } else {
      throw FormatException('unknown Datatype for VerificationMethod');
    }
  }
}

abstract class EmbeddedVerificationMethod
    implements VerificationMethod, JsonObject {
  @override
  final String id;

  @override
  final String controller;

  @override
  final String type;

  EmbeddedVerificationMethod({
    required this.id,
    required this.controller,
    required this.type,
  });

  factory EmbeddedVerificationMethod.fromJson(dynamic input) {
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

class VerificationMethodJwk extends EmbeddedVerificationMethod {
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

class VerificationMethodMultibase extends EmbeddedVerificationMethod {
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

class VerificationMethodRef implements VerificationMethod {
  final EmbeddedVerificationMethod method;
  final Uri reference;

  VerificationMethodRef({this.reference, this.method});

  bool get isReference =>

  dynamic toJson();

  String? get idOrNull;

  VerificationRelationship resolveWith(Map<String, VerificationMethod> veriMap);
}
