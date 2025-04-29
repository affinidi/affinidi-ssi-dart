import 'dart:collection';

import '../../../../ssi.dart';
import '../../../util/json_util.dart';
import '../../proof/embedded_proof.dart';
import '../field_types/credential_status/v2.dart';
import '../field_types/credential_subject.dart';
import '../field_types/evidence.dart';
import '../field_types/issuer.dart';
import '../field_types/refresh_service/v2.dart';
import '../field_types/terms_of_use.dart';

part './mutable_vc_data_model_v2.dart';

class VcDataModelV2 implements VerifiableCredential {
  @override
  final UnmodifiableListView<String> context;

  @override
  final Uri? id;

  @override
  final UnmodifiableSetView<String> type;

  @override
  final Issuer issuer;

  @override
  final UnmodifiableListView<CredentialSubject> credentialSubject;

  @override
  final UnmodifiableListView<EmbeddedProof> proof;

  @override
  final UnmodifiableListView<CredentialSchema> credentialSchema;

  @override
  final DateTime? validFrom;

  @override
  final DateTime? validUntil;

  final UnmodifiableListView<CredentialStatusV2> credentialStatus;

  final UnmodifiableListView<RefreshServiceV2> refreshService;

  @override
  final UnmodifiableListView<TermsOfUse> termsOfUse;

  final UnmodifiableListView<Evidence> evidence;

  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer.toJson();
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

  bool validate() {
    if (context.isEmpty) {
      throw SsiException(
        message: '`${_P.context.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (context.first != DMV2ContextUrl) {
      throw SsiException(
        message:
            'The first URI of `${_P.context.key}` property should always be $DMV2ContextUrl',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (type.isEmpty) {
      throw SsiException(
        message: '`${_P.type.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (credentialSubject.isEmpty) {
      throw SsiException(
        message: '`${_P.credentialSubject.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    return true;
  }

  VcDataModelV2({
    required List<String> context,
    this.id,
    required List<CredentialSubject> credentialSubject,
    required this.issuer,
    required Set<String> type,
    this.validFrom,
    this.validUntil,
    List<CredentialSchema>? credentialSchema,
    List<EmbeddedProof>? proof,
    List<CredentialStatusV2>? credentialStatus,
    List<RefreshServiceV2>? refreshService,
    List<TermsOfUse>? termsOfUse,
    List<Evidence>? evidence,
  })  : context = UnmodifiableListView(context),
        credentialSubject = UnmodifiableListView(credentialSubject),
        type = UnmodifiableSetView(type),
        proof = UnmodifiableListView(proof ?? []),
        credentialSchema = UnmodifiableListView(credentialSchema ?? []),
        credentialStatus = UnmodifiableListView(credentialStatus ?? []),
        refreshService = UnmodifiableListView(refreshService ?? []),
        termsOfUse = UnmodifiableListView(termsOfUse ?? []),
        evidence = UnmodifiableListView(evidence ?? []) {
    validate();
  }

  factory VcDataModelV2.fromJson(dynamic input) {
    final json = jsonToMap(input);

    final context = getStringList(json, _P.context.key, mandatory: true);

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

    final validFrom = getDateTime(json, _P.validFrom.key);

    final validUntil = getDateTime(json, _P.validUntil.key);

    final credentialStatus = parseListOrSingleItem<CredentialStatusV2>(
        json,
        _P.credentialStatus.key,
        (item) => CredentialStatusV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final refreshService = parseListOrSingleItem<RefreshServiceV2>(
        json,
        _P.refreshService.key,
        (item) => RefreshServiceV2.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final termsOfUse = parseListOrSingleItem<TermsOfUse>(
        json,
        _P.termsOfUse.key,
        (item) => TermsOfUse.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    final evidence = parseListOrSingleItem<Evidence>(json, _P.evidence.key,
        (item) => Evidence.fromJson(item as Map<String, dynamic>),
        allowSingleValue: true);

    return VcDataModelV2(
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

  VcDataModelV2.clone(VcDataModelV2 input)
      : this(
            context: input.context,
            id: input.id,
            credentialSubject: input.credentialSubject,
            issuer: input.issuer,
            type: input.type,
            validFrom: input.validFrom,
            credentialSchema: input.credentialSchema,
            validUntil: input.validUntil,
            proof: input.proof,
            credentialStatus: input.credentialStatus,
            refreshService: input.refreshService,
            termsOfUse: input.termsOfUse,
            evidence: input.evidence);
}
