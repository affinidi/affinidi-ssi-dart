import 'dart:convert';

import '../models/parsed_vp.dart';
import '../models/v2/vp_data_model_v2.dart';

class LdVpDataModelV2 extends VpDataModelV2
    implements ParsedVerifiablePresentation<String> {
  String? _serialized;

  LdVpDataModelV2({
    required super.context,
    required super.id,
    required super.holder,
    required super.type,
    super.proof,
    super.verifiableCredential,
    super.termsOfUse,
    required String serialized,
  }) : _serialized = serialized;

  LdVpDataModelV2.fromJson(super.input)
      : // use parsing from VcDataModelV1
        super.fromJson();

  LdVpDataModelV2.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized {
    _serialized ??= jsonEncode(toJson());
    return _serialized!;
  }
}
