part of 'vc_data_model_v2.dart';

class MutableVcDataModelV2 extends _VcDataModelV2View {
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
  DateTime? validFrom;

  @override
  DateTime? validUntil;

  @override
  List<EmbeddedProof> proof;

  @override
  List<MutableCredentialStatusV2> credentialStatus;

  @override
  List<MutableRefreshServiceV2> refreshService;

  @override
  List<MutableTermsOfUse> termsOfUse;

  @override
  List<MutableEvidence> evidence;

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
}

abstract interface class _VcDataModelV2View {
  List<String> get context;

  Uri? get id;

  Set<String> get type;

  List<MutableCredentialSchema> get credentialSchema;

  List<CredentialSubjectInterface> get credentialSubject;

  MutableIssuer? get issuer;

  DateTime? get validFrom;

  DateTime? get validUntil;

  List<EmbeddedProof> get proof;

  List<MutableCredentialStatusV2> get credentialStatus;

  List<MutableRefreshServiceV2> get refreshService;

  List<MutableTermsOfUse> get termsOfUse;

  List<MutableEvidence> get evidence;

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
