import 'package:http/http.dart' as http;

import '../../../ssi.dart';
import '../did.dart';

/// Represents a DID URL for the 'webvh' method, with support for SCID and encoded URL string.
///
/// Provides parsing, validation, conversion to HTTPS URLs, and resolution of DID documents.
class DidWebVhUrl extends DidUrl {
  /// The Secure Content Identifier (SCID) component of the DID URL.
  String scid;

  /// The encoded URL string component of the DID URL.
  String encodedUrlString;

  /// Constructs a [DidWebVhUrl] with the given components.
  DidWebVhUrl._({
    required super.scheme,
    required super.method,
    required super.methodSpecificId,
    required this.scid,
    required this.encodedUrlString,
    super.path,
    super.query,
    super.fragment,
  }) : super.internal();

  /// Parses a [DidWebVhUrl] from a string.
  ///
  /// Throws [SsiException] or [FormatException] if the string is not a valid DID WebVH URL.
  factory DidWebVhUrl.fromUrlString(String didUrlString) {
    final didUrl = DidUrl.fromUrlString(didUrlString);

    _validateMethod(didUrl.method);

    final (scid, encodedUrlString) = _parseMethodSpecificId(
      didUrl.methodSpecificId,
      didUrlString,
    );

    _validateScidAndEncodedUrl(scid, encodedUrlString, didUrlString);
    _validateDomain(encodedUrlString, didUrlString);
    _validateVersionQueryParameters(didUrl.query, didUrlString);

    return DidWebVhUrl._(
      scheme: didUrl.scheme,
      method: didUrl.method,
      methodSpecificId: didUrl.methodSpecificId,
      scid: scid,
      encodedUrlString: encodedUrlString,
      path: didUrl.path,
      query: didUrl.query,
      fragment: didUrl.fragment,
    );
  }

  /// Returns the HTTPS URL for the JSON log file associated with this DID WebVH URL.
  String get jsonLogFileHttpsUrlString {
    final hasEmptyPath = Uri.parse(toHttpsUrlString()).hasEmptyPath;
    return '${toHttpsUrlString()}${hasEmptyPath ? '/.well-known' : ''}/did.jsonl';
  }

  /// Returns the HTTPS URL for the witness file associated with this DID WebVH URL.
  String get witnessUrlString {
    final hasEmptyPath = Uri.parse(toHttpsUrlString()).hasEmptyPath;
    return '${toHttpsUrlString()}${hasEmptyPath ? '/.well-known' : ''}/did-witness.json';
  }

  /// Returns the HTTPS URL for the WhoIs service associated with this DID WebVH URL.
  String get whoIsServiceHttpsUrlString {
    final hasEmptyPath = Uri.parse(toHttpsUrlString()).hasEmptyPath;
    return '${toHttpsUrlString()}${hasEmptyPath ? '/.well-known' : ''}/whois.vp';
  }

  /// Resolves the DID document for this DID WebVH URL.
  ///
  /// Downloads the log file and verifies it, returning the DID document and metadata.
  Future<(DidDocument, DidDocumentMetadata?, DidResolutionMetadata?)>
      resolveDidWithMetadata([DidResolutionOptions? options]) async {
    final nnOptions = options ?? {};
    final http.Client? client = nnOptions['httpClient'];
    final didWebVhLog1 = await downloadWebVhLog(client);
    for (var entry in queryParameters.entries) {
      if (!nnOptions.keys.contains(entry.key)) {
        nnOptions[entry.key] = entry.value;
      }
    }
    nnOptions['resolvingDidUrl'] = this;
    final (doc, dm, rm) = await didWebVhLog1.verify(nnOptions);
    return (doc, dm, rm);
  }

  /// Resolves the DID document for this DID.
  ///
  /// **Parameters:**
  /// * `options` - Optional [DidResolutionOptions] to customize the resolution process.
  ///
  /// **Returns:**
  /// A [Future] that resolves to the [DidDocument] for this DID.
  ///
  /// **Throws:**
  /// Any exception thrown by [resolveDidWithMetadata] during the resolution process.
  @override
  Future<DidDocument> resolve([DidResolutionOptions? options]) async {
    final (didDoc, _, _) = await resolveDidWithMetadata(options);
    return didDoc;
  }

  /// Downloads the DID WebVH log file and parses it.
  ///
  /// Optionally accepts an [http.Client] for network requests.
  Future<DidWebVhLog> downloadWebVhLog([http.Client? client]) async {
    var jsonLogFile = await downloadDocument(
      Uri.parse(jsonLogFileHttpsUrlString),
      client: client,
    );
    return DidWebVhLog.fromJsonLines(jsonLogFile);
  }

  /// Converts the encoded URL string to an HTTPS URL.
  String toHttpsUrlString() {
    return parseHttpsUrlStringFromEncodedUrlString(encodedUrlString);
  }

  /// Converts an encoded URL string to an HTTPS URL.
  ///
  /// Replaces colons with slashes (except for percent-encoded ":" "%3A" port separators)
  /// and prepends `https://`.
  ///
  /// Example: `"example.com%3A8080:path"` → `"https://example.com:8080/path"`
  static String parseHttpsUrlStringFromEncodedUrlString(
      String encodedUrlString) {
    String urlString = encodedUrlString;

    urlString = urlString.replaceAll(':', '/');
    urlString = urlString.replaceAll('%3A', ':');
    urlString = 'https://$urlString';

    return urlString;
  }

  /// Validates that the DID method is 'webvh'.
  ///
  /// Throws [SsiException] if the method is not 'webvh'.
  static void _validateMethod(String method) {
    if (method != 'webvh') {
      throw SsiException(
          message: 'Unsupported DID method. Expected method: webvh',
          code: SsiExceptionType.invalidDidWebVh.code);
    }
  }

  /// Validates and parses the method-specific ID into SCID and encoded URL string.
  ///
  /// Returns a tuple of (scid, encodedUrlString).
  /// Throws [FormatException] if the method-specific ID is invalid.
  static (String, String) _parseMethodSpecificId(
      String methodSpecificId, String didUrlString) {
    final colonIndex = methodSpecificId.indexOf(':');

    if (colonIndex == -1) {
      throw FormatException(
        'Invalid DID WebVH URL: must contain scid and encodedUrlString separated by a colon. Received: $didUrlString',
        didUrlString,
      );
    }

    final scid = methodSpecificId.substring(0, colonIndex);
    final encodedUrlString = methodSpecificId.substring(colonIndex + 1);

    return (scid, encodedUrlString);
  }

  /// Validates that SCID and encoded URL string are not empty.
  ///
  /// Throws [FormatException] if either is empty.
  static void _validateScidAndEncodedUrl(
      String scid, String encodedUrlString, String didUrlString) {
    if (scid.isEmpty) {
      throw FormatException(
          'Invalid DID WebVH URL: scid cannot be empty', didUrlString);
    }
    if (encodedUrlString.isEmpty) {
      throw FormatException(
        'Invalid DID WebVH URL: encodedUrlString cannot be empty',
        didUrlString,
      );
    }
  }

  /// Validates that only one version query parameter is present.
  ///
  /// Throws [SsiException] if multiple version parameters are present.
  static void _validateVersionQueryParameters(
      String? query, String didUrlString) {
    final versionQueryParamCount = Uri(
      host: 'placeholder',
      query: query,
    )
        .queryParameters
        .entries
        .where((entry) =>
            ['versionId', 'versionTime', 'versionNumber'].contains(entry.key))
        .length;

    if (versionQueryParamCount > 1) {
      throw SsiException(
          message:
              'Only one of versionId, versionTime, or versionNumber is allowed in the query parameters',
          code: SsiExceptionType.invalidDidWebVh.code);
    }
  }

  /// Validates the domain part of an encoded URL string.
  ///
  /// Throws [FormatException] if the domain is invalid.
  static void _validateDomain(String encodedUrlString, String didUrlString) {
    final uriForCheck =
        Uri.parse(parseHttpsUrlStringFromEncodedUrlString(encodedUrlString));

    final cond1 = RegExp(r'[a-zA-Z]').hasMatch(uriForCheck.host);
    final cond2 = uriForCheck.host.contains('.');
    final cond3 = !uriForCheck.host.contains('[') &&
        !uriForCheck.host.contains(']') &&
        !uriForCheck.host.contains(':');

    if (!cond1 || !cond2 || !cond3) {
      throw FormatException(
        'Invalid DID WebVH URL: not a valid domain name that contains at least one dot and at least one letter, and must not contain brackets or colons. Received: $didUrlString',
        didUrlString,
      );
    }
  }
}
