import 'dart:collection';

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
part 'mutable_vc_data_model_v1.dart';

class VcDataModelV1 extends _VcDataModelV1 implements VerifiableCredential {
  static const String contextUrl = 'https://www.w3.org/2018/credentials/v1';

  @override
  final UnmodifiableListView<String> context; // Atleast one must

  @override
  final Uri? id;

  @override
  final UnmodifiableSetView<String> type;

  @override
  final Issuer issuer;

  @override
  final UnmodifiableListView<CredentialSubject> credentialSubject; // must

  @override
  final UnmodifiableListView<EmbeddedProof> proof; // must

  @override
  final UnmodifiableListView<CredentialSchema> credentialSchema;

  @override
  final DateTime issuanceDate;

  @override
  final DateTime? expirationDate;

  @override
  DateTime get validFrom => issuanceDate;

  @override
  DateTime? get validUntil => expirationDate;

  @override
  final Holder? holder;

  @override
  final CredentialStatusV1? credentialStatus;

  @override
  final UnmodifiableListView<RefreshServiceV1> refreshService;

  @override
  final UnmodifiableListView<TermsOfUse> termsOfUse;

  @override
  final UnmodifiableListView<Evidence> evidence;

  VcDataModelV1._({
    required List<String> context,
    this.id,
    required List<CredentialSubject> credentialSubject,
    required this.issuer,
    required Set<String> type,
    required this.issuanceDate,
    List<CredentialSchema>? credentialSchema,
    this.expirationDate,
    this.holder,
    List<EmbeddedProof>? proof,
    this.credentialStatus,
    List<RefreshServiceV1>? refreshService,
    List<TermsOfUse>? termsOfUse,
    List<Evidence>? evidence,
  })  : context = UnmodifiableListView(context),
        credentialSubject = UnmodifiableListView(credentialSubject),
        type = UnmodifiableSetView(type),
        proof = UnmodifiableListView(proof ?? []),
        credentialSchema = UnmodifiableListView(credentialSchema ?? []),
        refreshService = UnmodifiableListView(refreshService ?? []),
        termsOfUse = UnmodifiableListView(termsOfUse ?? []),
        evidence = UnmodifiableListView(evidence ?? []);

  factory VcDataModelV1.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key, mandatory: true);
    if (context.isEmpty || context.first != contextUrl) {
      throw SsiException(
        message:
            'The first URI of @context property should always be $contextUrl',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    final id = getUri(json, _P.id.key);
    final type = getStringList(
      json,
      _P.type.key,
      allowSingleValue: true,
      mandatory: true,
    ).toSet();

    final issuer = Issuer.fromJson(json[_P.issuer.key]);

    final credentialSubject = parseListOrSingleItem<CredentialSubject>(
        json,
        _P.credentialSubject.key,
        (item) => CredentialSubject.fromJson(item as Map<String, dynamic>),
        mandatory: true,
        allowSingleValue: true);

    final proof = parseListOrSingleItem<EmbeddedProof>(json, _P.proof.key,
        (item) => EmbeddedProof.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final credentialSchema = parseListOrSingleItem<CredentialSchema>(
        json,
        _P.credentialSchema.key,
        (item) => CredentialSchema.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final issuanceDate =
        getDateTime(json, _P.issuanceDate.key, mandatory: true)!;

    final expirationDate = getDateTime(json, _P.expirationDate.key);

    Holder? holder;
    if (json.containsKey(_P.holder.key)) {
      holder = Holder.fromJson(json[_P.holder.key]);
    }

    CredentialStatusV1? credentialStatus;
    if (json.containsKey(_P.credentialStatus.key)) {
      credentialStatus = CredentialStatusV1.fromJson(
          json[_P.credentialStatus.key] as Map<String, dynamic>);
    }

    final refreshService = parseListOrSingleItem<RefreshServiceV1>(
        json,
        _P.refreshService.key,
        (item) => RefreshServiceV1.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final termsOfUse = parseListOrSingleItem<TermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => TermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final evidence = parseListOrSingleItem<Evidence>(json, _P.evidence.key,
        (item) => Evidence.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return VcDataModelV1._(
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

  VcDataModelV1.clone(VcDataModelV1 input)
      : this._(
            context: input.context,
            id: input.id,
            credentialSubject: input.credentialSubject,
            issuer: input.issuer,
            type: input.type,
            issuanceDate: input.issuanceDate,
            credentialSchema: input.credentialSchema,
            expirationDate: input.expirationDate,
            holder: input.holder,
            proof: input.proof,
            credentialStatus: input.credentialStatus,
            refreshService: input.refreshService,
            termsOfUse: input.termsOfUse,
            evidence: input.evidence);
}
