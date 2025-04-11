import '../models/parsed_vc.dart';
import '../models/v2/vc_data_model_v2.dart';

class LdVcDataModelV2 extends VcDataModelV2
    implements ParsedVerifiableCredential<String> {
  String _serialized;

  LdVcDataModelV2({
    required super.context,
    required super.id,
    super.credentialSchema,
    super.credentialSubject,
    required super.issuer,
    required super.type,
    super.validFrom,
    super.validUntil,
    super.holder,
    super.proof,
    super.credentialStatus,
    required serialized,
  }) : _serialized = serialized;

  LdVcDataModelV2.fromJson(super.input)
      : _serialized = "",
        // use parsing from VcDataModelV1
        super.fromJson();

  /// Parse the input
  factory LdVcDataModelV2.parse(String jsonStr) {
    final result = LdVcDataModelV2.fromJson(jsonStr);
    result._serialized = jsonStr;

    return result;
  }

  @override
  String get serialized => _serialized;
}
