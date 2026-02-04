import 'package:http/http.dart' as http;

import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';

/// WebVhUrl Class to handle Url parsing and components
class DidWebVhUrl {
  /// Self Certifying IDentifier (SCID)
  final String scid;

  /// Uri in this DidWebVhUrl
  final Uri uri;

  DidWebVhUrl._(
    this.scid,
    this.uri,
  );

  /// Creates a WebVhUrl from a DID string
  factory DidWebVhUrl.fromDid(String did) {
    final String methodPrefix = 'did:webvh:';
    if (!did.startsWith(methodPrefix)) {
      throw SsiException(
          message: 'Unsupported DID method. Did must start with $methodPrefix',
          code: SsiExceptionType.invalidDidWebVh.code);
    }
    final String methodSpecificId = did.replaceFirst(methodPrefix, '');
    final [scid, ...urlParts] = methodSpecificId.split(':');

    String urlString = urlParts.join(':');

    String? fragment;
    if (urlString.contains('#')) {
      [urlString, fragment] = urlString.split('#');
    }

    String? query;
    if (urlString.contains('?')) {
      [urlString, query] = urlString.split('?');
    }

    urlString = urlString.replaceAll(':', '/');
    urlString = urlString.replaceAll('%3A', ':');
    urlString = urlString.replaceAll('%2B', '/');
    urlString = 'https://$urlString';

    query != null //
        ? urlString = '$urlString?$query'
        : urlString = urlString;
    fragment != null
        ? urlString = '$urlString#$fragment'
        : urlString = urlString;

    final didUrl = Uri.parse(urlString);

    /// Only one of versionId, versionTime, or versionNumber is allowed in the query parameters
    final versionQueryParamCount = didUrl.queryParameters.entries
        .where((entry) =>
            ['versionId', 'versionTime', 'versionNumber'].contains(entry.key))
        .length;

    if (versionQueryParamCount > 1) {
      throw SsiException(
          message:
              'Only one of versionId, versionTime, or versionNumber is allowed in the query parameters',
          code: SsiExceptionType.invalidDidWebVh.code);
    }

    return DidWebVhUrl._(
      scid,
      didUrl,
    );
  }

  /// Converts this DidWebVhUrl back to a DID string
  String toDid() {
    var urlAsString = uri.toString();
    urlAsString = urlAsString.replaceFirst(
        uri.authority, uri.authority.replaceAll(':', '%3A'));
    urlAsString = urlAsString.replaceFirst(uri.scheme, '');
    urlAsString = urlAsString.substring(3);
    urlAsString = urlAsString.replaceAll('/', ':');
    return 'did:webvh:$scid:$urlAsString';
  }

  /// Converts this DidWebVhUrl to a URL string pointing to its JSON log file
  String toJsonLogFileUrl() {
    var urlAsString = uri.toString();
    if (uri.hasEmptyPath) {
      urlAsString = '$urlAsString/.well-known';
    }
    return '$urlAsString/did.jsonl';
  }

  /// Downloads the JSON log file from the URL represented by this DidWebVhUrl
  Future<http.Response> downloadJsonLogFile([http.Client? client]) async {
    client ??= http.Client();
    try {
      var res = await client
          .get(Uri.parse(toJsonLogFileUrl()))
          .timeout(const Duration(seconds: 30), onTimeout: () {
        return http.Response('Timeout', 408);
      });

      if (res.statusCode == 200) {
        return res;
      } else {
        throw SsiException(
          message: 'Failed to fetch DIDWebVH JSON Log file for ${toDid()}',
          code: SsiExceptionType.invalidDidWebVh.code,
          originalMessage:
              'HTTP status code: ${res.statusCode} for URL: ${toJsonLogFileUrl()}',
        );
      }
    } catch (e) {
      // Re-throw if already an SsiException
      if (e is SsiException) rethrow;

      // Handle any HTTP errors (connection refused, timeouts, etc.)
      throw SsiException(
        message: 'Failed to fetch DIDWebVH JSON Log file for ${toDid()}: $e',
        code: SsiExceptionType.invalidDidWebVh.code,
      );
    }
  }
}
