import '../credential_schema.dart';
import '../verifiable_credential.dart';

// TODO must implement adapter functions where needed to the generic VerifiableCredential
class VcDataModelV2 implements VerifiableCredential {
  @override
  // TODO: implement credentialSchema
  List<CredentialSchema> get credentialSchema => throw UnimplementedError();

  @override
  // TODO: implement credentialSubject
  Map<String, dynamic> get credentialSubject => throw UnimplementedError();

  @override
  // TODO: implement id
  String get id => throw UnimplementedError();

  @override
  // TODO: implement issuer
  String get issuer => throw UnimplementedError();

  @override
  // TODO: implement rawData
  get rawData => throw UnimplementedError();

  @override
  toJson() {
    // TODO: implement toJson
    throw UnimplementedError();
  }

  @override
  // TODO: implement type
  List<String> get type => throw UnimplementedError();

  @override
  // TODO: implement validFrom
  DateTime? get validFrom => throw UnimplementedError();

  @override
  // TODO: implement validUntil
  DateTime? get validUntil => throw UnimplementedError();

  @override
  // TODO: implement context
  List<String> get context => throw UnimplementedError();
// @context
// String id;

// type
// name
// description
// issuer
// credentialSubject
// validFrom
// validUntil
// status
// credentialSchema
// refreshService
// termsOfUse
// evidence

// @override
// DateTime get issuanceDate => validFrom;
}
