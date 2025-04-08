import '../models/v1/parsed_vc_data_model_v1.dart';
import '../models/verifiable_credential.dart';
import 'vc_data_model_parser.dart';

/// Class to parse and convert a json representation of a [VerifiableCredential]
final class VcDataModelV1WithProofParser implements VcDataModelParser {
  static const _v1ContextUrl = 'https://www.w3.org/2018/credentials/v1';

  bool _hasV1Context(Object data) {
    if (data is! Map) return false;

    final context = data[VcDataModelV1Key.context.key];
    return (context is List) && context.contains(_v1ContextUrl);
  }

  /// Checks if the [data] provided matches the right criteria to attempt a parse
  @override
  bool canParse(Object data) {
    if (data is! Map) return false;
    if (!_hasV1Context(data)) return false;

    return data.containsKey(VcDataModelV1Key.proof.key);
  }

  /// Attempts to parse [data] and return a [VerifiableCredential]
  /// It can throw in case the data cannot be converted to a valid [VerifiableCredential]
  @override
  VerifiableCredential parse(Object data) {
    return ParsedVcDataModelV1(data as Map<String, dynamic>);
  }
}
