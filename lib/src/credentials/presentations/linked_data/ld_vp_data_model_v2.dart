import '../models/parsed_vp.dart';
import '../models/v2/vp_data_model_v2.dart';

class LdVpDataModelV2 extends VpDataModelV2
    implements ParsedVerifiablePresentation<String> {
  final String _serialized;

  LdVpDataModelV2.fromParsed(String serialized, super.input)
      : _serialized = serialized,
        // use parsing from VcDataModelV1
        super.fromJson();

  @override
  String get serialized {
    return _serialized;
  }
}
