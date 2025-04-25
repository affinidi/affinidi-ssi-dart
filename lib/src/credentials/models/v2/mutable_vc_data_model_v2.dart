import '../../proof/embedded_proof.dart';
import '../field_types/credential_schema.dart';
import '../field_types/credential_status/v2.dart';
import '../field_types/credential_subject.dart';
import '../field_types/evidence.dart';
import '../field_types/issuer.dart';
import '../field_types/refresh_service/v2.dart';
import '../field_types/terms_of_use.dart';
import 'vc_data_model_v2.dart';

class MutableVcDataModelV2 extends VcDataModelV2 {
  @override
  List<String> context;

  @override
  Uri? id;

  @override
  List<String> type;

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
  List<RefreshServiceV2> refreshService;

  @override
  List<TermsOfUse> termsOfUse;

  @override
  List<Evidence> evidence;

  MutableVcDataModelV2({
    List<String>? context,
    this.id,
    List<MutableCredentialSchema>? credentialSchema,
    List<MutableCredentialSubject>? credentialSubject,
    this.issuer,
    List<String>? type,
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
        type = type ?? [],
        proof = proof ?? [],
        refreshService = refreshService ?? [],
        termsOfUse = termsOfUse ?? [],
        evidence = evidence ?? [];
}
