import 'package:http/http.dart' as http;

import '../../../ssi.dart';
import '../did.dart';
import 'dart:io';

/// Represents a DID URL for the 'webvh' method, with support for SCID and encoded URL string.
///
/// Provides parsing, validation, conversion to HTTPS URLs, and resolution of DID documents.
class DidWebVhUrl extends DidUrl {
  /// The Secure Content Identifier (SCID) component of the DID URL.
  String scid;

  /// The encoded URL string component of the DID URL.
  String encodedUrlString;

  /// Constructs a [DidWebVhUrl] with the given components.
  DidWebVhUrl({
    required super.scheme,
    required super.method,
    required super.methodSpecificId,
    required this.scid,
    required this.encodedUrlString,
    super.path,
    super.query,
    super.fragment,
  });

  /// Parses a [DidWebVhUrl] from a string.
  ///
  /// Throws [SsiException] or [FormatException] if the string is not a valid DID WebVH URL.
  factory DidWebVhUrl.fromUrlString(String didUrlString) {
    final didUrl = DidUrl.fromUrlString(didUrlString);
    if (didUrl.method != 'webvh') {
      throw SsiException(
          message: 'Unsupported DID method. Expected method: webvh',
          code: SsiExceptionType.invalidDidWebVh.code);
    }
    final colonIndex = didUrl.methodSpecificId.indexOf(':');

    if (colonIndex == -1) {
      throw FormatException(
        'Invalid DID WebVH URL: must contain scid and encodedUrlString separated by a colon. Received: $didUrlString',
        didUrlString,
      );
    }

    final scid = didUrl.methodSpecificId.substring(0, colonIndex);
    final encodedUrlString = didUrl.methodSpecificId.substring(colonIndex + 1);

    if (null != InternetAddress.tryParse(encodedUrlString.split(':').first)) {
      throw FormatException(
          'Invalid DID WebVH domain name element  MUST NOT include IP addresses URL: MUST NOT include IP addresses',
          didUrlString);
    }

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

    final versionQueryParamCount = Uri(
      host: 'placeholder',
      query: didUrl.query,
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

    return DidWebVhUrl(
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

  /// Converts the encoded URL string to an HTTPS URL.
  String toHttpsUrlString() {
    String urlString = encodedUrlString;

    urlString = urlString.replaceAll(':', '/');
    urlString = urlString.replaceAll('%3A', ':');
    urlString = 'https://$urlString';

    return urlString;
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
  @override
  Future<(DidDocument, DidDocumentMetadata?, DidResolutionMetadata?)>
      resolveDid([DidResolutionOptions? options]) async {
    final nnOptions = options ?? {};
    final didWebVhLog1 = await downloadWebVhLog();
    for (var entry in queryParameters.entries) {
      if (!nnOptions.keys.contains(entry.key)) {
        nnOptions[entry.key] = entry.value;
      }
    }
    nnOptions['resolvingDidUrl'] = this;
    final (doc, dm, rm) = await didWebVhLog1.verify(nnOptions);
    return (doc, dm, rm);
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
}
