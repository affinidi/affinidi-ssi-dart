import '../models/v2/parsed_vc_data_model_v2.dart';
import '../models/verifiable_credential.dart';
import 'vc_data_model_parser.dart';

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class VcDataModelV2WithProofParser implements VcDataModelParser {
  static const _v2ContextUrl = 'https://www.w3.org/ns/credentials/v2';

  bool _hasV2Context(Object data) {
    if (data is! Map) return false;

    final context = data[VcDataModelV20Key.context.key];
    return (context is List) && context.contains(_v2ContextUrl);
  }

  /// Checks if the [data] provided matches the right criteria to attempt a parse
  @override
  bool canParse(Object data) {
    if (data is! Map) return false;
    if (!_hasV2Context(data)) return false;

    return data.containsKey(VcDataModelV20Key.proof.key);
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  VerifiableCredential parse(Object data) {
    return ParsedVcDataModelV2(data as Map<String, dynamic>);
  }
}
