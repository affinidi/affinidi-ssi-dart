part of 'vc_data_model_v1.dart';

class MutableVcDataModelV1 extends _VcDataModelV1 {
  @override
  List<String> context;

  @override
  Uri? id;

  @override
  Set<String> type;

  @override
  List<MutableCredentialSchema> credentialSchema;

  @override
  List<MutableCredentialSubject> credentialSubject;

  @override
  MutableIssuer? issuer;

  @override
  DateTime? issuanceDate;

  @override
  DateTime? expirationDate;

  @override
  MutableHolder? holder;

  @override
  List<EmbeddedProof> proof;

  @override
  MutableCredentialStatusV1? credentialStatus;

  @override
  List<MutableRefreshServiceV1> refreshService;

  @override
  List<MutableTermsOfUse> termsOfUse;

  @override
  List<MutableEvidence> evidence;

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
}

abstract interface class _VcDataModelV1 {
  List<String> get context;

  Uri? get id;

  List<MutableCredentialSchema> get credentialSchema;

  List<CredentialSubjectInterface> get credentialSubject;

  MutableIssuer? get issuer;

  Set<String> get type;

  List<EmbeddedProof> get proof;

  MutableCredentialStatusV1? get credentialStatus;

  DateTime? get issuanceDate;

  DateTime? get expirationDate;

  MutableHolder? get holder;

  List<MutableRefreshServiceV1> get refreshService;

  List<MutableTermsOfUse> get termsOfUse;

  List<MutableEvidence> get evidence;

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

    return json;
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
