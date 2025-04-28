part of 'vc_data_model_v1.dart';

const String DMV1ContextUrl = 'https://www.w3.org/2018/credentials/v1';

class MutableVcDataModelV1 {
  List<String> context;

  Uri? id;

  Set<String> type;

  List<MutableCredentialSchema> credentialSchema;

  List<MutableCredentialSubject> credentialSubject;

  MutableIssuer? issuer;

  DateTime? issuanceDate;

  DateTime? expirationDate;

  MutableHolder? holder;

  List<EmbeddedProof> proof;

  MutableCredentialStatusV1? credentialStatus;

  List<MutableRefreshServiceV1> refreshService;

  List<MutableTermsOfUse> termsOfUse;

  List<MutableEvidence> evidence;

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer?.toJson();
    json[_P.type.key] = type.toList();
    json[_P.id.key] = id?.toString();
    json[_P.credentialSchema.key] = encodeListToSingleOrArray(credentialSchema);
    json[_P.holder.key] = holder?.toJson();
    json[_P.issuanceDate.key] = issuanceDate?.toIso8601String();
    json[_P.expirationDate.key] = expirationDate?.toIso8601String();
    json[_P.credentialSubject.key] =
        encodeListToSingleOrArray(credentialSubject);
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.credentialStatus.key] = credentialStatus?.toJson();
    json[_P.refreshService.key] = encodeListToSingleOrArray(refreshService);
    json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    json[_P.evidence.key] = encodeListToSingleOrArray(evidence);

    return cleanEmpty(json);
  }

  MutableVcDataModelV1({
    List<String>? context,
    this.id,
    List<MutableCredentialSchema>? credentialSchema,
    List<MutableCredentialSubject>? credentialSubject,
    this.issuer,
    Set<String>? type,
    this.issuanceDate,
    this.expirationDate,
    this.holder,
    List<EmbeddedProof>? proof,
    this.credentialStatus,
    List<MutableRefreshServiceV1>? refreshService,
    List<MutableTermsOfUse>? termsOfUse,
    List<MutableEvidence>? evidence,
  })  : context = context ?? [],
        credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? [],
        type = type ?? {},
        proof = proof ?? [],
        refreshService = refreshService ?? [],
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [];

  factory MutableVcDataModelV1.fromJson(dynamic input) {
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

    final issuanceDate = getDateTime(json, _P.issuanceDate.key);
    final expirationDate = getDateTime(json, _P.expirationDate.key);

    final holder = MutableHolder.fromJson(json[_P.holder.key]);

    MutableCredentialStatusV1? credentialStatus;
    if (json.containsKey(_P.credentialStatus.key)) {
      credentialStatus = MutableCredentialStatusV1.fromJson(
          json[_P.credentialStatus.key] as Map<String, dynamic>);
    }

    final refreshService = parseListOrSingleItem<MutableRefreshServiceV1>(
        json,
        _P.refreshService.key,
        (item) =>
            MutableRefreshServiceV1.fromJson(item as Map<String, dynamic>),
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

    return MutableVcDataModelV1(
        context: context,
        id: id,
        credentialSubject: credentialSubject,
        issuer: issuer,
        type: type,
        issuanceDate: issuanceDate,
        credentialSchema: credentialSchema,
        expirationDate: expirationDate,
        holder: holder,
        proof: proof,
        credentialStatus: credentialStatus,
        refreshService: refreshService,
        termsOfUse: termsOfUse,
        evidence: evidence);
  }
}

typedef _P = VcDataModelV1Key;

enum VcDataModelV1Key {
  context(key: '@context'),
  proof,
  expirationDate,
  issuer,
  credentialSchema,
  credentialSubject,
  id,
  type,
  issuanceDate,
  credentialStatus,
  holder,
  refreshService,
  termsOfUse,
  evidence,
  ;

  final String? _key;

  String get key => _key ?? name;

  const VcDataModelV1Key({String? key}) : _key = key;
}
