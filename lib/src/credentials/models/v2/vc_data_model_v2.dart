import '../../../util/json_util.dart';
import '../../proof/embedded_proof.dart';
import '../field_types/credential_schema.dart';
import '../field_types/credential_status/v2.dart';
import '../field_types/credential_subject.dart';
import '../field_types/evidence.dart';
import '../field_types/issuer.dart';
import '../field_types/refresh_service/v2.dart';
import '../field_types/terms_of_use.dart';
import '../verifiable_credential.dart';

abstract class VcDataModelV2 implements VerifiableCredential {
  static const String contextUrl = 'https://www.w3.org/ns/credentials/v2';

  @override
  List<String> get context;

  @override
  Uri? get id;

  @override
  List<CredentialSchema> get credentialSchema;

  @override
  List<CredentialSubject> get credentialSubject;

  @override
  Issuer? get issuer;

  @override
  List<String> get type;

  @override
  DateTime? get validFrom;

  @override
  DateTime? get validUntil;

  @override
  List<EmbeddedProof> get proof;

  List<CredentialStatusV2> get credentialStatus;

  List<RefreshServiceV2> get refreshService;

  List<TermsOfUse> get termsOfUse;

  List<Evidence> get evidence;

  @override
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{};

    json[_P.context.key] = context;
    json[_P.issuer.key] = issuer?.toJson();
    json[_P.type.key] = type;
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

    return json;
  }
}

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
