import 'dart:convert';

import 'package:ssi/src/credentials/presentations/models/parsed_vp.dart';
import 'package:ssi/src/credentials/presentations/models/v2/vp_data_model_v2.dart';

class LdVpDataModelV2 extends VpDataModelV2
    implements ParsedVerifiablePresentation<String, VpDataModelV2> {
  String? _serialized;

  LdVpDataModelV2({
    required super.context,
    required super.id,
    required super.holder,
    required super.type,
    super.proof,
    super.verifiableCredential,
    super.termsOfUse,
    required serialized,
  }) : _serialized = serialized;

  LdVpDataModelV2.fromJson(super.input)
      : _serialized = input['serialized'],
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized {
    _serialized ??= jsonEncode(toJson());
    return _serialized!;
  }
}
