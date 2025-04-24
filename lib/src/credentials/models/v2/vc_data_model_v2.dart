import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';
import '../../../util/json_util.dart';
import '../../proof/embedded_proof.dart';
import '../credential_schema.dart';
import '../credential_status.dart';
import '../credential_subject.dart';
import '../issuer.dart';
import '../vc_models.dart';
import 'vc_data_model_v2_view.dart';

// TODO(FTL-20734): must match fields in the spec https://www.w3.org/TR/vc-data-model-2.0/#verifiable-credentials
class MutableVcDataModelV2 implements VcDataModelV2 {
  static const String contextUrl = 'https://www.w3.org/ns/credentials/v2';

  @override
  List<String> context;

  @override
  String? id;

  @override
  List<CredentialSchema> credentialSchema;

  @override
  CredentialStatus? credentialStatus;

  @override
  CredentialSubject credentialSubject;

  @override
  Issuer issuer;

  @override
  List<String> type;

  @override
  DateTime? validFrom;

  @override
  DateTime? validUntil;

  @override
  List<EmbeddedProof> proof;

  @override
  RefreshService? refreshService;

  @override
  List<TermOfUse> termsOfUse;

  @override
  List<Evidence> evidence;

  MutableVcDataModelV2({
    required this.context,
    this.id,
    List<CredentialSchema>? credentialSchema,
    CredentialSubject? credentialSubject,
    required this.issuer,
    required this.type,
    this.validFrom,
    this.validUntil,
    List<EmbeddedProof>? proof,
    this.credentialStatus,
    this.refreshService,
    List<TermOfUse>? termsOfUse,
    List<Evidence>? evidence,
  })  : credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? CredentialSubject(claims: {}),
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [],
        proof = proof ??
            [EmbeddedProof(type: 'Ed25519Signature2018', previousProof: [])];

  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer.toJson();
    json[_P.type.key] = type;

    if (id != null) {
      json[_P.id.key] = id;
    }

    if (credentialSchema.isNotEmpty) {
      json[_P.credentialSchema.key] =
          encodeListToSingleOrArray(credentialSchema);
    }

    final fromDate = validFrom;
    if (fromDate != null) {
      json[_P.validFrom.key] = fromDate.toIso8601String();
    }

    final untilDate = validUntil;
    if (untilDate != null) {
      json[_P.validUntil.key] = untilDate.toIso8601String();
    }

    json[_P.credentialSubject.key] = credentialSubject.toJson();

    // V2 spec expects a single proof object or an array
    json[_P.proof.key] = encodeListToSingleOrArray(proof);

    var credStatus = credentialStatus;
    if (credStatus != null) {
      json[_P.credentialStatus.key] = credStatus.toJson();
    }

    if (refreshService != null) {
      json[_P.refreshService.key] = refreshService!.toJson();
    }

    if (termsOfUse.isNotEmpty) {
      json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    }

    if (evidence.isNotEmpty) {
      json[_P.evidence.key] = encodeListToSingleOrArray(evidence);
    }

    return json;
  }

  MutableVcDataModelV2.fromJson(dynamic input)
      : context = [],
        credentialSchema = [],
        credentialSubject = CredentialSubject(claims: {}),
        issuer = Issuer(id: ''),
        type = [],
        proof = [],
        termsOfUse = [],
        evidence = [],
        refreshService = null {
    final json = jsonToMap(input);

    context = getStringList(json, _P.context.key, mandatory: true);
    id = getString(json, _P.id.key);

    issuer = Issuer.fromJson(json[_P.issuer.key]);

    type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    );

    validFrom = getDateTime(json, _P.validFrom.key);
    validUntil = getDateTime(json, _P.validUntil.key);

    if (json.containsKey(_P.credentialSubject.key)) {
      credentialSubject = CredentialSubject.fromJson(
          json[_P.credentialSubject.key] as Map<String, dynamic>);
    }

    switch (json[_P.credentialSchema.key]) {
      case Map m:
        credentialSchema = [CredentialSchema.fromJson(jsonToMap(m))];

      case List l:
        credentialSchema = l
            .map((e) => CredentialSchema.fromJson(jsonToMap(e)))
            .toList(growable: true);

      case null:
        break;

      default:
        throw SsiException(
          message: 'invalid credentialSchema',
          code: SsiExceptionType.invalidJson.code,
        );
    }

    if (json.containsKey(_P.proof.key)) {
      proof = parseListOrSingleItem<EmbeddedProof>(
        json[_P.proof.key],
        (item) => EmbeddedProof.fromJson(jsonToMap(item)),
      );
    }

    if (json.containsKey(_P.credentialStatus.key)) {
      credentialStatus = CredentialStatus.fromJson(
          json[_P.credentialStatus.key] as Map<String, dynamic>);
    }

    if (json.containsKey(_P.refreshService.key)) {
      refreshService =
          RefreshService.fromJson(jsonToMap(json[_P.refreshService.key]));
    }

    if (json.containsKey(_P.termsOfUse.key)) {
      termsOfUse = parseListOrSingleItem<TermOfUse>(
        json[_P.termsOfUse.key],
        (item) => TermOfUse.fromJson(jsonToMap(item)),
      );
    }

    if (json.containsKey(_P.evidence.key)) {
      evidence = parseListOrSingleItem<Evidence>(
        json[_P.evidence.key],
        (item) => Evidence.fromJson(jsonToMap(item)),
      );
    }
  }
}

/// Shortcut to make the code easier to read, p comes from property
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
