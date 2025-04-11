import 'dart:convert';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';

class LdVcDataModelV1 extends VcDataModelV1
    implements ParsedVerifiableCredential<String> {
  String? _serialized;

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
    required String serialized,
  }) : _serialized = serialized;

  LdVcDataModelV1.fromJson(super.input)
      : // use parsing from VcDataModelV1
        super.fromJson();

  LdVcDataModelV1.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized {
    _serialized ??= jsonEncode(toJson());
    return _serialized!;
  }

  @override
  Map<String, dynamic> toJson() {
    final s = _serialized;
    if (s == null) {
      throw SsiException(
        message: 'LdVcDataModelV1 is invalid, _serialized is null',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }
    return jsonDecode(s);
  }
}
