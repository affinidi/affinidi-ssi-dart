import 'package:ssi/src/credentials/models/field_types/evidence.dart';
import 'package:ssi/src/credentials/models/field_types/refresh_service/v1.dart';
import 'package:ssi/src/credentials/models/field_types/terms_of_use.dart';
import 'package:ssi/src/util/json_util.dart';

import '../field_types/credential_schema.dart';
import '../field_types/credential_status/v1.dart';
import '../field_types/credential_subject.dart';
import '../field_types/holder.dart';
import '../field_types/issuer.dart';
import '../../proof/embedded_proof.dart';
import '../verifiable_credential.dart';

abstract class VcDataModelV1 implements VerifiableCredential {
  static const String contextUrl = 'https://www.w3.org/2018/credentials/v1';

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
  List<EmbeddedProof> get proof;

  CredentialStatusV1? get credentialStatus;

  DateTime? get issuanceDate;

  DateTime? get expirationDate;

  Holder? get holder;

  List<RefreshServiceV1> get refreshService;

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
    json[_P.holder.key] = holder?.toJson();
    json[_P.issuanceDate.key] = issuanceDate?.toIso8601String();
    json[_P.expirationDate.key] = expirationDate?.toIso8601String();
    json[_P.credentialSubject.key] =
        encodeListToSingleOrArray(credentialSubject);
    json[_P.proof.key] = encodeListToSingleOrArray(proof);
    json[_P.credentialStatus.key] = credentialStatus?.toJson();
    json[_P.refreshService.key] = encodeListToSingleOrArray(refreshService);
    json[_P.termsOfUse.key] = encodeListToSingleOrArray(termsOfUse);
    json[_P.evidence.key] = encodeListToSingleOrArray(evidence);

    return json;
  }
}

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
