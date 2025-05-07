import 'dart:convert';
import 'dart:typed_data';

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../types.dart';
import '../../util/json_util.dart';
import '../public_key_utils.dart';
import 'did_document.dart';

/// Represents a verification method in a DID Document.
sealed class VerificationMethod {
  /// The identifier of the verification method.
  String get id;

  /// The controller of the verification method.
  String get controller;

  /// The type of the verification method.
  String get type;

  /// Whether this verification method is a reference.
  bool get isReference;

  /// Returns the JWK representation of the verification method.
  Jwk asJwk();

  /// Returns the multikey representation of the verification method.
  Uint8List asMultiKey();

  factory VerificationMethod.fromJson(
    dynamic value,
    Map<String, EmbeddedVerificationMethod> verificationMethodMap,
  ) {
    if (value is String) {
      final verificationMethod = verificationMethodMap[value];
      if (verificationMethod == null) {
        throw FormatException(
          'verification method reference "$value" not found',
        );
      }
      return VerificationMethodRef(
        reference: value,
        method: verificationMethod,
      );
    } else if (value is Map<String, dynamic>) {
      return EmbeddedVerificationMethod.fromJson(value);
    } else if (value is VerificationMethod) {
      return value;
    } else if (value is VerificationMethodRef) {
      return value;
    } else {
      throw const FormatException('unknown Datatype for VerificationMethod');
    }
  }

  /// Converts this verification method to a JSON-serializable map.
  dynamic toJson();
}

/// Represents an embedded verification method in a DID Document.
abstract class EmbeddedVerificationMethod
    implements VerificationMethod, JsonObject {
  /// The identifier of the embedded verification method.
  @override
  final String id;

  /// The controller of the embedded verification method.
  @override
  final String controller;

  /// The type of the embedded verification method.
  @override
  final String type;

  /// Whether this embedded verification method is a reference.
  @override
  bool get isReference => false;

  /// Creates an [EmbeddedVerificationMethod] instance.
  EmbeddedVerificationMethod({
    required this.id,
    required this.controller,
    required this.type,
  });

  /// Creates an [EmbeddedVerificationMethod] from JSON input.
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

  /// Converts this embedded verification method to a JSON-serializable map.
  @override
  Map<String, dynamic> toJson() {
    final jsonObject = <String, dynamic>{};
    jsonObject['id'] = id;
    jsonObject['controller'] = controller;
    jsonObject['type'] = type;

    return jsonObject;
  }

  /// Returns the JSON string representation of the embedded verification method.
  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

/// Represents a verification method using JWK.
class VerificationMethodJwk extends EmbeddedVerificationMethod {
  /// The public key in JWK format.
  final Jwk publicKeyJwk;

  /// Creates a [VerificationMethodJwk] instance.
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

/// Represents a verification method using multibase encoding.
class VerificationMethodMultibase extends EmbeddedVerificationMethod {
  /// The public key in multikey format.
  late final Uint8List publicKeyMultikey;

  /// The public key in multibase format.
  final String publicKeyMultibase;

  /// Creates a [VerificationMethodMultibase] instance.
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

/// Represents a reference to a verification method.
class VerificationMethodRef implements VerificationMethod {
  /// The embedded verification method being referenced.
  final EmbeddedVerificationMethod method;

  /// The reference string.
  final String reference;

  /// Creates a [VerificationMethodRef] instance.
  VerificationMethodRef({
    required this.reference,
    required this.method,
  });

  @override
  Jwk asJwk() => method.asJwk();

  @override
  Uint8List asMultiKey() => method.asMultiKey();

  @override
  String get controller => method.controller;

  @override
  String get id => method.id;

  @override
  dynamic toJson() => reference;

  @override
  String get type => method.type;

  @override
  bool get isReference => true;
}
