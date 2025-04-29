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

class VcDataModelV1 implements VerifiableCredential {
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

  final DateTime issuanceDate;

  final DateTime? expirationDate;

  @override
  DateTime get validFrom => issuanceDate;

  @override
  DateTime? get validUntil => expirationDate;

  final Holder? holder;

  final CredentialStatusV1? credentialStatus;

  final UnmodifiableListView<RefreshServiceV1> refreshService;

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
    json[_P.holder.key] = holder?.toJson();
    json[_P.issuanceDate.key] = issuanceDate.toIso8601String();
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

  bool validate() {
    if (context.isEmpty) {
      throw SsiException(
        message: '`${_P.context.key}` property is mandatory',
        code: SsiExceptionType.invalidJson.code,
      );
    }

    if (context.first != DMV1ContextUrl) {
      throw SsiException(
        message:
            'The first URI of `${_P.context.key}` property should always be $DMV1ContextUrl',
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

  VcDataModelV1({
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
        evidence = UnmodifiableListView(evidence ?? []) {
    validate();
  }

  factory VcDataModelV1.fromJson(dynamic input) {
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

    return VcDataModelV1(
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
      : this(
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

  factory VcDataModelV1.fromMutable(MutableVcDataModelV1 data) =>
      VcDataModelV1.fromJson(data.toJson());
}
