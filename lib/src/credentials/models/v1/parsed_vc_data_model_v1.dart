import '../../../../ssi.dart';
import '../../../util/json_util.dart';
import '../../proof/embedded_proof.dart';
import '../field_types/credential_status/v1.dart';
import '../field_types/credential_subject.dart';
import '../field_types/evidence.dart';
import '../field_types/holder.dart';
import '../field_types/issuer.dart';
import '../field_types/refresh_service/v1.dart';
import '../field_types/terms_of_use.dart';
import 'vc_data_model_v1.dart';

class ParsedVcDataModelV1 extends VcDataModelV1 {
  @override
  List<String> context; // Atleast one must

  @override
  Uri? id;

  @override
  List<String> type; // atleast one must

  @override
  Issuer issuer;

  @override
  List<ParsedCredentialSubject> credentialSubject; // must

  @override
  List<EmbeddedProof> proof; // must

  @override
  List<ParsedCredentialSchema> credentialSchema; // optional

  @override
  DateTime issuanceDate;

  @override
  DateTime? expirationDate;

  @override
  DateTime get validFrom => issuanceDate;

  @override
  DateTime? get validUntil => expirationDate;

  @override
  Holder? holder;

  @override
  ParsedCredentialStatusV1? credentialStatus;

  @override
  List<ParsedRefreshServiceV1> refreshService;

  @override
  List<ParsedTermsOfUse> termsOfUse;

  @override
  List<ParsedEvidence> evidence;

  ParsedVcDataModelV1._({
    required this.context,
    this.id,
    required this.credentialSubject,
    required this.issuer,
    required this.type,
    required this.issuanceDate,
    List<ParsedCredentialSchema>? credentialSchema,
    this.expirationDate,
    this.holder,
    required this.proof,
    this.credentialStatus,
    List<ParsedRefreshServiceV1>? refreshService,
    List<ParsedTermsOfUse>? termsOfUse,
    List<ParsedEvidence>? evidence,
  })  : credentialSchema = credentialSchema ?? [],
        refreshService = refreshService ?? [],
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [];

  factory ParsedVcDataModelV1.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key, mandatory: true);
    final id = getUri(json, _P.id.key);
    final type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    );

    final issuer = ParsedIssuer.fromJson(json[_P.issuer.key]);

    final credentialSubject = parseListOrSingleItem<ParsedCredentialSubject>(
        json,
        _P.credentialSubject.key,
        (item) =>
            ParsedCredentialSubject.fromJson(item as Map<String, dynamic>),
        mandatory: true,
        allowSingleValue: true);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        mandatory: true, allowSingleValue: true);

    final credentialSchema = parseListOrSingleItem<ParsedCredentialSchema>(
        json,
        _P.credentialSchema.key,
        (item) => ParsedCredentialSchema.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final issuanceDate =
        getDateTime(json, _P.issuanceDate.key, mandatory: true)!;

    final expirationDate = getDateTime(json, _P.expirationDate.key);

    ParsedHolder? holder;
    if (json.containsKey(_P.holder.key)) {
      holder = ParsedHolder.fromJson(json[_P.holder.key]);
    }

    ParsedCredentialStatusV1? credentialStatus;
    if (json.containsKey(_P.credentialStatus.key)) {
      credentialStatus = ParsedCredentialStatusV1.fromJson(
          json[_P.credentialStatus.key] as Map<String, dynamic>);
    }

    final refreshService = parseListOrSingleItem<ParsedRefreshServiceV1>(
        json,
        _P.refreshService.key,
        (item) => ParsedRefreshServiceV1.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final termsOfUse = parseListOrSingleItem<ParsedTermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => ParsedTermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final evidence = parseListOrSingleItem<ParsedEvidence>(
        json,
        _P.evidence.key,
        (item) => ParsedEvidence.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return ParsedVcDataModelV1._(
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
