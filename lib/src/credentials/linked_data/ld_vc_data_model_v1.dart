import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';

class LdVcDataModelV1 extends VcDataModelV1
    implements ParsedVerifiableCredential<String, VcDataModelV1> {
  String _serialized;

  LdVcDataModelV1({
    required super.context,
    required super.id,
    super.credentialSchema,
    super.credentialSubject,
    required super.issuer,
    required super.type,
    super.issuanceDate,
    super.expirationDate,
    super.holder,
    super.proof,
    super.credentialStatus,
    required serialized,
  }) : _serialized = serialized;

  LdVcDataModelV1.fromJson(super.input)
      : _serialized = "",
        // use parsing from VcDataModelV1
        super.fromJson();

  /// Parse the input
  factory LdVcDataModelV1.parse(String jsonStr) {
    final result = LdVcDataModelV1.fromJson(jsonStr);
    result._serialized = jsonStr;

    return result;
  }

  @override
  String get serialized => _serialized;
}
