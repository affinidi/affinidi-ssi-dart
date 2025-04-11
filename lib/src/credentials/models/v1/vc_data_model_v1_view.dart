import '../credential_schema.dart';
import '../credential_status.dart';
import '../verifiable_credential.dart';

abstract interface class VcDataModelV1 implements VerifiableCredential {
  @override
  List<String> get context;

  @override
  String? get id;

  @override
  List<CredentialSchema> get credentialSchema;

  @override
  CredentialStatus? get credentialStatus;

  @override
  Map<String, dynamic> get credentialSubject;

  @override
  String get issuer;

  @override
  List<String> get type;

  DateTime? get issuanceDate;

  DateTime? get expirationDate;

  Map<String, dynamic> get holder;

  @override
  Map<String, dynamic> get proof;
}
