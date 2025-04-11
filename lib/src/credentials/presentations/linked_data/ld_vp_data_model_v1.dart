import 'dart:convert';

import '../models/parsed_vp.dart';
import '../models/v1/vp_data_model_v1.dart';

class LdVpDataModelV1 extends VpDataModelV1
    implements ParsedVerifiablePresentation<String> {
  String? _serialized;

  LdVpDataModelV1({
    required super.context,
    required super.id,
    required super.holder,
    required super.type,
    super.proof,
    super.verifiableCredential,
    required String serialized,
  }) : _serialized = serialized;

  LdVpDataModelV1.fromJson(super.input)
      : // use parsing from VcDataModelV1
        super.fromJson();

  LdVpDataModelV1.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized {
    _serialized ??= jsonEncode(toJson());
    return _serialized!;
  }
}
