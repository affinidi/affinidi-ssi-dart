import '../../proof/embedded_proof.dart';
import '../field_types/credential_schema.dart';
import '../field_types/credential_status/v1.dart';
import '../field_types/credential_subject.dart';
import '../field_types/evidence.dart';
import '../field_types/holder.dart';
import '../field_types/issuer.dart';
import '../field_types/refresh_service/v1.dart';
import '../field_types/terms_of_use.dart';
import 'vc_data_model_v1.dart';

class MutableVcDataModelV1 extends VcDataModelV1 {
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
  DateTime? get validFrom => issuanceDate;

  @override
  DateTime? get validUntil => expirationDate;

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
