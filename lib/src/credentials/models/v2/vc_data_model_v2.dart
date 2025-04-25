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

class VcDataModelV2 extends _VcDataModelV2View implements VerifiableCredential {
  static const String contextUrl = 'https://www.w3.org/ns/credentials/v2';

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

  @override
  final UnmodifiableListView<CredentialStatusV2> credentialStatus;

  @override
  final UnmodifiableListView<RefreshServiceV2> refreshService;

  @override
  final UnmodifiableListView<TermsOfUse> termsOfUse;

  @override
  final UnmodifiableListView<Evidence> evidence;

  VcDataModelV2._({
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
        evidence = UnmodifiableListView(evidence ?? []);

  factory VcDataModelV2.fromJson(dynamic input) {
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

    final validFrom = getDateTime(json, _P.validFrom.key, mandatory: true)!;

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

    return VcDataModelV2._(
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
