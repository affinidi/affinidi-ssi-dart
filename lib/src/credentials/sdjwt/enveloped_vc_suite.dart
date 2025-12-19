import '../../did/did_resolver.dart';
import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../models/parsed_vc.dart';
import '../models/v2/vc_data_model_v2.dart';
import '../parsers/ld_parser.dart';
import '../suites/vc_suite.dart';
import '../suites/vc_suites.dart';
import 'sdjwt_dm_v2_suite.dart';

/// Enum representing supported media types for enveloped Verifiable Credentials.
enum MediaTypes {
  /// Media type for SD-JWT encoded Verifiable Credentials.
  sdJwt('data:application/vc+sd-jwt,');

  /// The associated media type string.
  final String type;
  const MediaTypes(this.type);
}

/// Mapping between media type strings and their corresponding VC suites.
final Map<String, VerifiableCredentialSuite> mediaTypeSuites = {
  MediaTypes.sdJwt.type: SdJwtDm2Suite()
};

/// Suite for working with W3C VC Data Model v2 credentials in SD-JWT format.
///
/// Provides methods to parse, validate, and issue Verifiable Credentials
/// represented as Selective Disclosure JWT (SD-JWT) according to the
/// W3C Data Model v2 specification.
final class EnvelopedVcDm2Suite
    with
        LdParser
    implements
        VerifiableCredentialSuite<String, VcDataModelV2,
            ParsedVerifiableCredential<String>> {
  @override
  bool hasValidPayload(Map<String, dynamic> data) {
    final context = data[VcDataModelV2Key.context.key];
    final type = data[VcDataModelV2Key.type.key];
    final envelopedData = data['id'];

    return (context is List) &&
        context.contains(dmV2ContextUrl) &&
        (type != null) &&
        (type is List) &&
        (type.contains('EnvelopedVerifiableCredential')) &&
        (envelopedData != null) &&
        (envelopedData is String) &&
        mediaTypeSuites.keys.any(envelopedData.startsWith);
  }

  /// Checks if [input] can be parsed by this suite.
  ///
  /// Returns `true` if [input] is a decodable String.
  @override
  bool canParse(Object input) {
    if (input is! String) return false;
    return canDecode(input);
  }

  /// Parses an [input] string into a [ParsedVerifiableCredential].
  ///
  /// Throws a [SsiException] if [input] is not a String or invalid.
  @override
  ParsedVerifiableCredential<String> parse(Object input) {
    if (input is! String) {
      throw SsiException(
        message: 'Only String is supported',
        code: SsiExceptionType.invalidEncoding.code,
      );
    }

    final parsed = decode(input);
    final envelopedData = parsed['id'] as String;

    final mediaType = mediaTypeSuites.entries
        .firstWhere((e) => envelopedData.startsWith(e.key));

    final serialized = envelopedData.replaceFirst(mediaType.key, '');

    return mediaType.value.parse(serialized)
        as ParsedVerifiableCredential<String>;
  }

  /// Attempts to parse the [input] and returns the result if successful, null otherwise.
  ///
  /// This method combines validation and parsing in one step to avoid redundant operations.
  @override
  ParsedVerifiableCredential<String>? tryParse(Object input) {
    if (!canParse(input)) return null;

    try {
      return parse(input);
    } catch (e) {
      return null;
    }
  }

  @override
  Future<bool> verifyIntegrity(ParsedVerifiableCredential<String> input,
      {DateTime Function() getNow = DateTime.now,
      DidResolver? didResolver}) async {
    throw SsiException(
      message: 'Call verification on ${VcSuites.getVcSuite(input).runtimeType}',
      code: SsiExceptionType.unsupportedEnvelopeVCOperation.code,
    );
  }

  @override
  Map<String, dynamic> present(ParsedVerifiableCredential<String> input) {
    final suite = VcSuites.getVcSuite(input);
    final mediaTypeEntry = mediaTypeSuites.entries
        .firstWhere((e) => e.value.runtimeType == suite.runtimeType,
            orElse: () => throw SsiException(
                  message:
                      'Enveloped VC Presentation for "${input.runtimeType}" is not supported',
                  code: SsiExceptionType.other.code,
                ));

    return _envelope(mediaTypeEntry.key, input);
  }

  Map<String, dynamic> _envelope(
      String mediaType, ParsedVerifiableCredential credential) {
    return {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      'id': '$mediaType${credential.serialized}',
      'type': ['EnvelopedVerifiableCredential'],
    };
  }
}
