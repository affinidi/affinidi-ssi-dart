import '../../../exceptions/ssi_exception.dart';
import '../../../exceptions/ssi_exception_type.dart';
import '../../../util/json_util.dart';
import '../../proof/embedded_proof.dart';
import '../credential_schema.dart';
import '../credential_status.dart';
import '../credential_subject.dart';
import '../holder.dart';
import '../issuer.dart';
import '../vc_models.dart';
import 'vc_data_model_v1_view.dart';

// TODO(FTL-20734): must match fields in the spec https://www.w3.org/TR/vc-data-model/
class MutableVcDataModelV1 implements VcDataModelV1 {
  static const String contextUrl = 'https://www.w3.org/2018/credentials/v1';

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
  DateTime? issuanceDate;

  @override
  DateTime? expirationDate;

  @override
  DateTime? get validFrom => issuanceDate;

  @override
  DateTime? get validUntil => expirationDate;

  @override
  Holder? holder;

  @override
  List<EmbeddedProof> proof;

  @override
  RefreshService? refreshService;

  @override
  List<TermOfUse> termsOfUse;

  @override
  List<Evidence> evidence;

  MutableVcDataModelV1({
    required this.context,
    this.id,
    List<CredentialSchema>? credentialSchema,
    CredentialSubject? credentialSubject,
    required this.issuer,
    required this.type,
    this.issuanceDate,
    this.expirationDate,
    this.holder,
    List<EmbeddedProof>? proof,
    this.credentialStatus,
    this.refreshService,
    List<TermOfUse>? termsOfUse,
    List<Evidence>? evidence,
  })  : credentialSchema = credentialSchema ?? [],
        credentialSubject = credentialSubject ?? CredentialSubject(claims: {}),
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [],
        proof = proof ?? [EmbeddedProof(type: 'Ed25519Signature2018')];

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

    final issDate = issuanceDate;
    if (issDate != null) {
      json[_P.issuanceDate.key] = issDate.toIso8601String();
    }

    final expDate = expirationDate;
    if (expDate != null) {
      json[_P.expirationDate.key] = expDate.toIso8601String();
    }

    json[_P.credentialSubject.key] = credentialSubject.toJson();

    if (holder != null) {
      json[_P.holder.key] = holder!.toJson();
    }

    // V1 spec expects a single proof object, not an array
    if (proof.isNotEmpty) {
      json[_P.proof.key] = proof.first.toJson();
    }

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

  MutableVcDataModelV1.fromJson(dynamic input)
      : context = [],
        credentialSchema = [],
        credentialSubject = CredentialSubject(claims: {}),
        holder = null,
        issuer = Issuer(id: ''),
        type = [],
        proof = [],
        termsOfUse = [],
        evidence = [],
        refreshService = null {
    final json = jsonToMap(input);

    context = getStringList(json, _P.context.key, mandatory: true);
    id = getString(json, _P.id.key);

    // Parse issuer - can be string or object
    issuer = Issuer.fromJson(json[_P.issuer.key]);

    type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    );

    issuanceDate = getDateTime(json, _P.issuanceDate.key);
    expirationDate = getDateTime(json, _P.expirationDate.key);

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

    if (json.containsKey(_P.holder.key)) {
      holder = Holder.fromJson(json[_P.holder.key]);
    }

    // V1 spec expects a single proof object, not an array
    if (json.containsKey(_P.proof.key)) {
      proof = [
        EmbeddedProof.fromJson(json[_P.proof.key] as Map<String, dynamic>)
      ];
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
