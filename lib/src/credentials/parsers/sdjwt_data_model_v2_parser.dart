import '../models/v2/parsed_vc_data_model_v2.dart';
import '../models/v2/sdjwt_data_model_v2.dart';
import '../models/verifiable_credential.dart';
import 'vc_data_model_parser.dart';

/// Class to parse and convert a json representation of a [SdjwtDataModelV2]
final class SdJwtDataModelV2Parser implements VcDataModelParser {
  static const _v2ContextUrl = 'https://www.w3.org/ns/credentials/v2';

  bool _hasV2Context(Object data) {
    if (data is! Map) return false;

    final context = data[VcDataModelV20Key.context.key];
    return (context is List) && context.contains(_v2ContextUrl);
  }

  /// Checks if the [data] provided matches the right criteria to attempt a parse
  @override
  bool canParse(Object data) {
    // FIXME check if data is a valid encoding

    if (data is! Map) return false;
    if (!_hasV2Context(data)) return false;

    return data.containsKey(VcDataModelV20Key.proof.key);
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  SdjwtDataModelV2 parse(Object data) {
    // call the sdjwt lib parse code
    return SdjwtDataModelV2(data as Map<String, dynamic>);
  }
}
