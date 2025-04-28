import 'verification_method.dart';

sealed class VerificationRelationship {
  const VerificationRelationship();

  factory VerificationRelationship.fromJson(dynamic value) {
    if (value is String) {
      return VerificationRelationshipId(value);
    } else if (value is Map<String, dynamic>) {
      return VerificationRelationshipMethod(
          EmbeddedVerificationMethod.fromJson(value));
    } else if (value is VerificationMethod) {
      return VerificationRelationshipMethod(value);
    } else if (value is VerificationRelationship) {
      return value;
    } else {
      throw FormatException('unknown Datatype for VerificationRelationship');
    }
  }

  dynamic toJson();

  String? get idOrNull;

  VerificationRelationship resolveWith(Map<String, VerificationMethod> veriMap);
}

class VerificationRelationshipId extends VerificationRelationship {
  final String id;

  const VerificationRelationshipId(this.id);

  @override
  dynamic toJson() => id;

  @override
  String? get idOrNull => id;

  @override
  VerificationRelationship resolveWith(
      Map<String, VerificationMethod> veriMap) {
    final method = veriMap[id];

    return method != null ? VerificationRelationshipMethod(method) : this;
  }
}

class VerificationRelationshipMethod extends VerificationRelationship {
  final VerificationMethod method;

  const VerificationRelationshipMethod(this.method);

  @override
  dynamic toJson() => method.toJson();

  @override
  String? get idOrNull => method.id;

  @override
  VerificationRelationship resolveWith(
          Map<String, VerificationMethod> veriMap) =>
      this;
}
