import 'dart:convert';

import '../models/parsed_vp.dart';
import '../models/v1/vp_data_model_v1.dart';

class LdVpDataModelV1 extends VpDataModelV1
    implements ParsedVerifiablePresentation<String> {
  final String _serialized;

  LdVpDataModelV1.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized {
    return _serialized;
  }
}
