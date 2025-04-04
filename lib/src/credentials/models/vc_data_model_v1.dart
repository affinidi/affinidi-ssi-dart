import 'credential_schema.dart';
import 'verifiable_credential.dart';

// TODO must implement adapter functions where needed to the generic VerifiableCredential
// TODO decide what to do with "holder"
class VcDataModelV1 implements VerifiableCredential {
  @override
  List<String> context;

  @override
  String id;

  @override
  List<CredentialSchema> credentialSchema;

  @override
  Map<String, dynamic> credentialSubject;

  @override
  String issuer;

  @override
  List<String> type;

  DateTime? issuanceDate;

  DateTime? expirationDate;

  @override
  DateTime? get validFrom => issuanceDate;

  @override
  DateTime? get validUntil => expirationDate;

  VcDataModelV1({
    required this.context,
    required this.id,
    List<CredentialSchema>? credentialSchema,
    Map<String, dynamic>? credentialSubject,
    required this.issuer,
    required this.type,
    this.issuanceDate,
    this.expirationDate,
  })  : credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? {};

  @override
  // TODO: implement rawData
  get rawData => throw UnimplementedError();

  @override
  Map<String, dynamic> toJson() {
    final Map<String, dynamic> json = {};

    json['@context'] = context;
    json['id'] = id;
    json['issuer'] = issuer;
    json['type'] = type;

    if (credentialSchema.isNotEmpty) {
      json['credentialSchema'] = _encodeCredentialSchema(credentialSchema);
    }

    final issDate = issuanceDate;
    if (issDate != null) {
      json['issuanceDate'] = issDate.toIso8601String();
    }

    final expDate = expirationDate;
    if (expDate != null) {
      json['issuanceDate'] = expDate.toIso8601String();
    }

    if (credentialSubject.isNotEmpty) {
      json['credentialSubject'] = credentialSubject;
    }

    return json;
  }

  dynamic _encodeCredentialSchema(
    List<CredentialSchema> credentialSchema,
  ) {
    if (credentialSchema.length == 1) {
      return credentialSchema.first.toJson();
    }

    return credentialSchema.fold(
      [],
      (list, cs) {
        list.add(cs.toJson());
        return list;
      },
    );
  }
}
