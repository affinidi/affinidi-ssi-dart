import '../credential_schema.dart';
import '../verifiable_credential.dart';

// TODO must implement adapter functions where needed to the generic VerifiableCredential
// TODO(cm): must match fields in the spec https://www.w3.org/TR/vc-data-model-2.0/#verifiable-credentials
class VcDataModelV2 implements VerifiableCredential<Map<String, dynamic>> {
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
  Map<String, dynamic>  toJson() {
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
