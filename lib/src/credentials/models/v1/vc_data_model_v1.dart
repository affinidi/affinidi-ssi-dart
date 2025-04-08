import '../../../util/json_util.dart';
import '../credential_schema.dart';
import '../verifiable_credential.dart';

// TODO(cm) must implement adapter functions where needed to the generic VerifiableCredential
// TODO(cm) decide what to do with "holder"
// TODO(cm): add validation against the VCDM1 schema somewhere
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

  Map<String, dynamic> holder;

  Map<String, dynamic> proof;

  VcDataModelV1({
    required this.context,
    required this.id,
    List<CredentialSchema>? credentialSchema,
    Map<String, dynamic>? credentialSubject,
    required this.issuer,
    required this.type,
    this.issuanceDate,
    this.expirationDate,
    Map<String, String>? holder,
    Map<String, String>? proof,
  })  : credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? {},
        holder = holder ?? {},
        proof = proof ?? {};

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
      json['expirationDate'] = expDate.toIso8601String();
    }

    if (credentialSubject.isNotEmpty) {
      json['credentialSubject'] = credentialSubject;
    }

    if (holder.isNotEmpty) {
      json['holder'] = holder;
    }

    if (proof.isNotEmpty) {
      json['proof'] = proof;
    }

    return json;
  }

  VcDataModelV1.fromJson(dynamic input)
      : context = [],
        credentialSchema = [],
        credentialSubject = {},
        holder = {},
        id = "",
        issuer = "",
        type = [],
        proof = {} {
    final json = jsonToMap(input);

    context = getStringList(json, '@context', mandatory: true);
    id = getMandatoryString(json, 'id');
    issuer = getMandatoryString(json, 'issuer');
    type = getStringList(
      json,
      'type',
      allowSingleValue: true,
      mandatory: true,
    );

    // if (holder.isNotEmpty) {
    //   json['holder'] = holder;
    // }

    issuanceDate = getDateTime(json, 'issuanceDate');
    expirationDate = getDateTime(json, 'expirationDate');

    // FIXME handle arrays of subjects
    credentialSubject = Map.of(json['credentialSubject']);

    switch (json['credentialSchema']) {
      case Map m:
        credentialSchema = [CredentialSchema.fromJson(jsonToMap(m))];

      case List l:
        credentialSchema = l
            .map((e) => CredentialSchema.fromJson(jsonToMap(e)))
            .toList(growable: true);
    }

    // FIXME handle simple string
    if (json['holder'] != null && json['holder'] is Map) {
      holder = Map.of(json['holder']);
    }

    // FIXME use a typed object
    if (json['proof'] != null && json['proof'] is Map) {
      proof = Map.of(json['proof']);
    }
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
