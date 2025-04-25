import 'package:ssi/src/credentials/models/field_types/evidence.dart';
import 'package:ssi/src/credentials/models/field_types/refresh_service/v1.dart';
import 'package:ssi/src/credentials/models/field_types/terms_of_use.dart';

import '../field_types/credential_schema.dart';
import '../field_types/credential_status/v1.dart';
import '../field_types/credential_subject.dart';
import '../field_types/issuer.dart';
import '../../proof/embedded_proof.dart';
import '../verifiable_credential.dart';
import '../field_types/vc_models.dart';

abstract interface class VcDataModelV2 implements VerifiableCredential {
  @override
  List<String> get context;

  @override
  String? get id;

  @override
  List<MutableCredentialSchema> get credentialSchema;

  @override
  CredentialStatusV1? get credentialStatus;

  @override
  MutableCredentialSubject get credentialSubject;

  @override
  Issuer get issuer;

  @override
  List<String> get type;

  @override
  DateTime? get validFrom;

  @override
  DateTime? get validUntil;

  @override
  List<EmbeddedProof> get proof;

  @override
  RefreshServiceV1? get refreshService;

  @override
  List<TermOfUse> get termsOfUse;

  @override
  List<Evidence> get evidence;
}
