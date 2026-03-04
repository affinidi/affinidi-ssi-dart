import 'package:http/http.dart' as http;

import '../../../ssi.dart';
import '../did.dart';

/// Options for resolving a DID with the 'did:webvh' method.
///
/// This class extends [DidResolutionOptions] to provide configuration
/// specific to the WebVH DID resolution process.
class DidWebVhResolutionOptions extends DidResolutionOptions {
  /// The DID URL being resolved. Used for validation and metadata.
  DidWebVhUrl? resolvingDidUrl;

  /// Specific version ID to resolve (format: "versionNumber-entryHash").
  String? versionId;

  /// Specific timestamp to resolve. Returns the last version at or before this time.
  DateTime? versionTime;

  /// Specific version number to resolve (e.g., 1, 2, 3).
  int? versionNumber;

  /// Custom HTTP client for network requests. If null, a default client is used.
  http.Client? httpClient;

  /// If true, skips verification that entry hashes match the canonicalized entry content.
  bool? skipHashEntryVerification;

  /// If true, skips all proof-related verifications including signatures and key authorization.
  bool? skipAllProofRelatedVerification;

  /// If true, skips validation of key pre-rotation constraints.
  bool? skipKeyPreRotationVerification;

  /// If true, skips witness proof verification for entries requiring witnesses.
  bool? skipWitnessVerification;

  /// If true, skips verification that the SCID matches the hash of the first entry.
  bool? skipScidVerification;

  /// If true, skips adding default services (#whois, #files) to the resolved DID Document.
  bool? skipDefaultServiceAddition;

  /// If true, skips validation that the SCID in the resolved DID Document matches active parameters.
  bool? skipResolvedDidDocScidVerification;

  /// If true, skips validation of DID Document portability constraints.
  bool? skipDidDocPortabilityVerification;

  /// If true, skips cryptographic proof signature verification.
  bool? skipProofVerification;

  /// If true, skips checking that signing keys are in the active updateKeys list.
  bool? skipActiveUpdateKeysCheck;

  /// Configuration options for resolving DID WebVH identifiers.
  ///
  /// This class specifies the parameters used when resolving a DID WebVH,
  /// including network preferences and other resolution-related settings.
  DidWebVhResolutionOptions({
    this.resolvingDidUrl,
    this.versionId,
    this.versionTime,
    this.versionNumber,
    this.httpClient,
    this.skipHashEntryVerification,
    this.skipAllProofRelatedVerification,
    this.skipKeyPreRotationVerification,
    this.skipWitnessVerification,
    this.skipScidVerification,
    this.skipDefaultServiceAddition,
    this.skipResolvedDidDocScidVerification,
    this.skipDidDocPortabilityVerification,
    this.skipProofVerification,
    this.skipActiveUpdateKeysCheck,
  });
}

/// Metadata associated with the resolution of a DID WebVH document.
///
/// This class extends [DidResolutionMetadata] and provides metadata specific
/// to the WebVH DID method resolution process.
class DidWebVhResolutionMetadata extends DidResolutionMetadata {
  /// Optional details about any problems encountered during DID WebVH processing.
  ///
  /// This field may contain error messages or additional information about
  /// issues that occurred when validating or resolving the DID.
  String? problemDetails;

  /// Creates a new instance of [DidWebVhResolutionMetadata].
  ///
  /// This constructor initializes the resolution metadata for a DID WebVH resolution result.
  DidWebVhResolutionMetadata({
    this.problemDetails,
  });
}

/// Metadata for a DID WebVH document.
///
/// This class extends [DidDocumentMetadata] and represents metadata specific to
/// DID documents that use the WebVH (Web Verifiable Hash) method.
class DidWebVhDocumentMetadata extends DidDocumentMetadata {
  /// The Self-Certifying Identifier (SCID) for this DID.
  ///
  /// A hash of the DID's inception event that serves as a cryptographic
  /// commitment to the initial state of the DID.
  String? scid;

  /// The version identifier of the resolved DID Document.
  ///
  /// Format: "versionNumber-entryHash" (e.g., "3-z6Mk...")
  String? versionId;

  /// The timestamp when this version of the DID Document was created.
  ///
  /// Represented as a UTC DateTime value.
  DateTime? versionTime;

  /// The sequential version number of the resolved DID Document.
  ///
  /// Starts at 1 for the first entry and increments by 1 for each subsequent version.
  int? versionNumber;

  /// Creates a new instance of [DidWebVhDocumentMetadata].
  ///
  /// This constructor initializes a DID WebVH document metadata object with the provided parameters.
  DidWebVhDocumentMetadata({
    this.scid,
    this.versionId,
    this.versionTime,
    this.versionNumber,
  });

  Map<String, dynamic> toJson() {
    return {
      'scid': scid,
      'versionId': versionId,
      'versionTime': versionTime?.toIso8601String(),
      'versionNumber': versionNumber,
    };
  }
}

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

  /// Resolves a DID WebVH URL string and returns the DID Document.
  ///
  /// This is a convenience method that combines parsing and resolution in one call.
  /// It parses the DID string, downloads and verifies the log file, and returns
  /// the resolved DID Document.
  ///
  /// **Parameters:**
  /// * `didUrlString` - The DID WebVH URL string to resolve (e.g., "did:webvh:scid:example.com")
  /// * `options` - Optional [DidWebVhResolutionOptions] to customize the resolution process
  ///
  /// **Returns:**
  /// A [Future] that resolves to the [DidDocument] for the specified DID.
  ///
  /// **Throws:**
  /// * [FormatException] if the DID string is malformed
  /// * [SsiException] if resolution or verification fails
  ///
  /// **Example:**
  /// ```dart
  /// final didDoc = await DidWebVhUrl.resolve('did:webvh:z123:example.com');
  /// print(didDoc.id);
  /// ```
  static Future<DidDocument> resolve(
    String didUrlString, {
    DidWebVhResolutionOptions? options,
  }) async {
    final didWebVhUrl = DidWebVhUrl.fromUrlString(didUrlString);
    return didWebVhUrl.resolveDid(options: options);
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
  Future<(DidDocument, DidDocumentMetadata, DidResolutionMetadata)>
      resolveDidWithMetadata({DidWebVhResolutionOptions? options}) async {
    final nnOptions = options ?? DidWebVhResolutionOptions();
    nnOptions.resolvingDidUrl = this;

    final didWebVhLog1 = await downloadWebVhLog(client: nnOptions.httpClient);
    nnOptions.versionId = nnOptions.versionId ?? queryParameters['versionId'];
    nnOptions.versionTime = nnOptions.versionTime ??
        (queryParameters['versionTime'] != null
            ? DateTime.parse(queryParameters['versionTime']!)
            : null);
    nnOptions.versionNumber = nnOptions.versionNumber ??
        (queryParameters['versionNumber'] != null
            ? int.parse(queryParameters['versionNumber']!)
            : null);
    return didWebVhLog1.verify(options: nnOptions);
  }

  /// Resolves the DID document for this DID.
  ///
  /// **Parameters:**
  /// * `options` - Optional [DidWebVhResolutionOptions] to customize the resolution process.
  ///
  /// **Returns:**
  /// A [Future] that resolves to the [DidDocument] for this DID.
  ///
  /// **Throws:**
  /// Any exception thrown by [resolveDidWithMetadata] during the resolution process.
  @override
  Future<DidDocument> resolveDid({DidResolutionOptions? options}) async {
    final (didDoc, _, _) = await resolveDidWithMetadata(
        options: options as DidWebVhResolutionOptions?);
    return didDoc;
  }

  /// Downloads the DID WebVH log file and parses it.
  ///
  /// Optionally accepts an [http.Client] for network requests.
  Future<DidWebVhLog> downloadWebVhLog({http.Client? client}) async {
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
