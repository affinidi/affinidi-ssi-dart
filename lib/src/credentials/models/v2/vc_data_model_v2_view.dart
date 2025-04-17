import '../credential_schema.dart';
import '../credential_status.dart';
import '../credential_subject.dart';
import '../holder.dart';
import '../issuer.dart';
import '../proof.dart';
import '../verifiable_credential.dart';

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
  Proof get proof;

  @override
  Map<String, dynamic>? get refreshService;

  @override
  List<Map<String, dynamic>> get termsOfUse;

  @override
  List<Map<String, dynamic>> get evidence;
}
