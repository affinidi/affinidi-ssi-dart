import 'dart:convert';

import 'package:ssi/src/credentials/presentations/models/parsed_vp.dart';
import 'package:ssi/src/credentials/presentations/models/v1/vp_data_model_v1.dart';

class LdVpDataModelV1 extends VpDataModelV1
    implements ParsedVerifiablePresentation<String, VpDataModelV1> {
  String? _serialized;

  LdVpDataModelV1({
    required super.context,
    required super.id,
    required super.holder,
    required super.type,
    super.proof,
    super.verifiableCredential,
    required serialized,
  }) : _serialized = serialized;

  LdVpDataModelV1.fromJson(super.input)
      : _serialized = input['serialized'],
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized {
    _serialized ??= jsonEncode(toJson());
    return _serialized!;
  }
}
