import '../credential_schema.dart';
import '../credential_status.dart';
import '../credential_subject.dart';
import '../holder.dart';
import '../issuer.dart';
import '../../proof/embedded_proof.dart';
import '../verifiable_credential.dart';
import '../vc_models.dart';

abstract interface class VcDataModelV2 implements VerifiableCredential {
  @override
  List<String> get context;

  @override
  String? get id;

  @override
  List<CredentialSchema> get credentialSchema;

  @override
  CredentialStatus? get credentialStatus;

  @override
  CredentialSubject get credentialSubject;

  @override
  Issuer get issuer;

  @override
  List<String> get type;

  @override
  DateTime? get validFrom;

  @override
  DateTime? get validUntil;

  @override
  Holder? get holder;

  @override
  EmbeddedProof get proof;

  @override
  RefreshService? get refreshService;

  @override
  List<TermOfUse> get termsOfUse;

  @override
  List<Evidence> get evidence;
}
