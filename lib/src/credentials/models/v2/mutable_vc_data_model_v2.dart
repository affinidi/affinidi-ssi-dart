part of 'vc_data_model_v2.dart';

const String DMV2ContextUrl = 'https://www.w3.org/ns/credentials/v2';

class MutableVcDataModelV2 {
  List<String> context;

  Uri? id;

  Set<String> type;

  List<MutableCredentialSchema> credentialSchema;

  List<MutableCredentialSubject> credentialSubject;

  MutableIssuer? issuer;

  DateTime? validFrom;

  DateTime? validUntil;

  List<EmbeddedProof> proof;

  List<MutableCredentialStatusV2> credentialStatus;

  List<MutableRefreshServiceV2> refreshService;

  List<MutableTermsOfUse> termsOfUse;

  List<MutableEvidence> evidence;

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer?.toJson();
    json[_P.type.key] = type.toList();
    json[_P.id.key] = id?.toString();
    json[_P.credentialSchema.key] = encodeListToSingleOrArray(credentialSchema);
    json[_P.validFrom.key] = validFrom?.toIso8601String();
    json[_P.validUntil.key] = validUntil?.toIso8601String();
    json[_P.credentialSubject.key] =
        encodeListToSingleOrArray(credentialSubject);
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.credentialStatus.key] = encodeListToSingleOrArray(credentialStatus);
    json[_P.refreshService.key] = encodeListToSingleOrArray(refreshService);
    json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    json[_P.evidence.key] = encodeListToSingleOrArray(evidence);

    return cleanEmpty(json);
  }

  MutableVcDataModelV2({
    List<String>? context,
    this.id,
    List<MutableCredentialSchema>? credentialSchema,
    List<MutableCredentialSubject>? credentialSubject,
    this.issuer,
    Set<String>? type,
    this.validFrom,
    this.validUntil,
    List<EmbeddedProof>? proof,
    List<MutableCredentialStatusV2>? credentialStatus,
    List<MutableRefreshServiceV2>? refreshService,
    List<MutableTermsOfUse>? termsOfUse,
    List<MutableEvidence>? evidence,
  })  : context = context ?? [],
        credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? [],
        credentialStatus = credentialStatus ?? [],
        type = type ?? {},
        proof = proof ?? [],
        refreshService = refreshService ?? [],
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [];

  factory MutableVcDataModelV2.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key);

    final id = getUri(json, _P.id.key);
    final type =
        getStringList(json, _P.type.key, allowSingleValue: true).toSet();

    final issuer = MutableIssuer.fromJson(json[_P.issuer.key]);

    final credentialSubject = parseListOrSingleItem<MutableCredentialSubject>(
        json,
        _P.credentialSubject.key,
        (item) =>
            MutableCredentialSubject.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentialSchema = parseListOrSingleItem<MutableCredentialSchema>(
        json,
        _P.credentialSchema.key,
        (item) =>
            MutableCredentialSchema.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final validFrom = getDateTime(json, _P.validFrom.key);

    final validUntil = getDateTime(json, _P.validUntil.key);

    final credentialStatus = parseListOrSingleItem<MutableCredentialStatusV2>(
        json,
        _P.credentialStatus.key,
        (item) =>
            MutableCredentialStatusV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final refreshService = parseListOrSingleItem<MutableRefreshServiceV2>(
        json,
        _P.refreshService.key,
        (item) =>
            MutableRefreshServiceV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final termsOfUse = parseListOrSingleItem<MutableTermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => MutableTermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final evidence = parseListOrSingleItem<MutableEvidence>(
        json,
        _P.evidence.key,
        (item) => MutableEvidence.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return MutableVcDataModelV2(
        context: context,
        id: id,
        credentialSubject: credentialSubject,
        issuer: issuer,
        type: type,
        validFrom: validFrom,
        credentialSchema: credentialSchema,
        validUntil: validUntil,
        proof: proof,
        credentialStatus: credentialStatus,
        refreshService: refreshService,
        termsOfUse: termsOfUse,
        evidence: evidence);
  }
}

typedef _P = VcDataModelV2Key;

enum VcDataModelV2Key {
  context(key: '@context'),
  proof,
  issuer,
  credentialSchema,
  credentialSubject,
  id,
  type,
  validFrom,
  validUntil,
  credentialStatus,
  refreshService,
  termsOfUse,
  evidence,
  ;

  final String? _key;

  String get key => _key ?? name;

  const VcDataModelV2Key({String? key}) : _key = key;
}
