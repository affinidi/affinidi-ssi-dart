import '../../../../ssi.dart';
import '../../../util/json_util.dart';
import '../../proof/embedded_proof.dart';
import '../field_types/credential_status/v2.dart';
import '../field_types/credential_subject.dart';
import '../field_types/evidence.dart';
import '../field_types/issuer.dart';
import '../field_types/refresh_service/v2.dart';
import '../field_types/terms_of_use.dart';
import 'vc_data_model_v2.dart';

class ParsedVcDataModelV2 extends VcDataModelV2 {
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
  DateTime? validFrom;

  @override
  DateTime? validUntil;

  @override
  List<ParsedCredentialStatusV2> credentialStatus;

  @override
  List<ParsedRefreshServiceV2> refreshService;

  @override
  List<ParsedTermsOfUse> termsOfUse;

  @override
  List<ParsedEvidence> evidence;

  ParsedVcDataModelV2._({
    required this.context,
    this.id,
    required this.credentialSubject,
    required this.issuer,
    required this.type,
    this.validFrom,
    this.validUntil,
    List<ParsedCredentialSchema>? credentialSchema,
    required this.proof,
    List<ParsedCredentialStatusV2>? credentialStatus,
    List<ParsedRefreshServiceV2>? refreshService,
    List<ParsedTermsOfUse>? termsOfUse,
    List<ParsedEvidence>? evidence,
  })  : credentialSchema = credentialSchema ?? [],
        credentialStatus = credentialStatus ?? [],
        refreshService = refreshService ?? [],
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [];

  factory ParsedVcDataModelV2.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key, mandatory: true);
    if (context.isEmpty || context.first != VcDataModelV2.contextUrl) {
      throw SsiException(
        message:
            'The first URI of @context property should always be ${VcDataModelV2.contextUrl}',
        code: SsiExceptionType.invalidJson.code,
      );
    }

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
        mandatory: false, allowSingleValue: true);

    final credentialSchema = parseListOrSingleItem<ParsedCredentialSchema>(
        json,
        _P.credentialSchema.key,
        (item) => ParsedCredentialSchema.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final validFrom = getDateTime(json, _P.validFrom.key, mandatory: true)!;

    final validUntil = getDateTime(json, _P.validUntil.key);

    final credentialStatus = parseListOrSingleItem<ParsedCredentialStatusV2>(
        json,
        _P.credentialStatus.key,
        (item) =>
            ParsedCredentialStatusV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final refreshService = parseListOrSingleItem<ParsedRefreshServiceV2>(
        json,
        _P.refreshService.key,
        (item) => ParsedRefreshServiceV2.fromJson(item as Map<String, dynamic>),
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

    return ParsedVcDataModelV2._(
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
