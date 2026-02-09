// ignore_for_file: public_member_api_docs

import '../../../ssi.dart';

enum UrlType {
  didDoc,
  whois,
}

class WebvhUrlX {
  WebvhUrlX._({
    required this.type,
    required this.didUrl,
    required this.scid,
    required this.domain,
    required this.path,
    this.port,
    this.fragment,
    this.query,
    this.fileName,
    this.queryVersionId,
    this.queryVersionTime,
    this.queryVersionNumber,
  });

  final UrlType type;
  // full url
  final String didUrl;
  final String scid;
  final String domain;
  final int? port;
  // with a trailing slash, example: "/.well-known/" or "/custom/path/"
  final String path;
  final String? fragment;
  final String? query;
  final String? fileName;
  final String? queryVersionId;
  final DateTime? queryVersionTime;
  final int? queryVersionNumber;

  // format: `did:webvh:SCID:domain[:port][:path]?query#fragment`
  static WebvhUrlX parseDidUrl(String url) {
    String urlWithoutPrefix;
    if (url.startsWith('did:webvh:')) {
      urlWithoutPrefix = url.substring('did:webvh:'.length);
    } else if (url.startsWith('did:')) {
      throw SsiException(
          message: 'Unsupported DID method. Did must start with did:webvh:',
          code: SsiExceptionType.invalidDidWebVh.code);
    } else {
      urlWithoutPrefix = url;
    }

    String prefix;
    String? fragment;
    final fragmentIndex = urlWithoutPrefix.indexOf('#');
    if (fragmentIndex != -1) {
      prefix = urlWithoutPrefix.substring(0, fragmentIndex);
      fragment = urlWithoutPrefix.substring(fragmentIndex + 1);
    } else {
      prefix = urlWithoutPrefix;
    }

    String? query;
    final queryIndex = prefix.indexOf('?');
    if (queryIndex != -1) {
      query = prefix.substring(queryIndex + 1);
      prefix = prefix.substring(0, queryIndex);
    }

    final (queryVersionId, queryVersionTime, queryVersionNumber) =
        _parseQuery(query);

    final parts = prefix.split(':');
    if (parts.length < 2) {
      throw SsiException(
          message: 'Invalid URL: Must contain SCID and domain',
          code: SsiExceptionType.invalidDidWebVh.code);
    }

    final scid = parts[0];

    // Parse domain and optional port
    String domain;
    int? port;
    final domainPart = parts[1];
    if (domainPart.contains('%3A')) {
      final domainParts = domainPart.split('%3A');
      domain = domainParts[0];
      final portStr = domainParts[1];
      port = int.tryParse(portStr);
      if (port == null) {
        throw SsiException(
            message: 'Invalid URL: Port ($portStr) must be a number',
            code: SsiExceptionType.invalidDidWebVh.code);
      }
    } else {
      domain = domainPart;
    }

    final pathBuffer = StringBuffer();
    String fileName = 'did.jsonl';
    // var isWhois = false;

    for (var i = 2; i < parts.length; i++) {
      if (parts[i] != 'whois') {
        pathBuffer.write('/');
        pathBuffer.write(parts[i]);
      }
    }

    var path = pathBuffer.toString();
    if (path.isEmpty) {
      path = '/.well-known/';
    } else {
      path = '$path/';
    }

    // Check for whois
    UrlType type;
    if (parts.length > 2 && parts.last == 'whois') {
      if (path == '/.well-known/') {
        path = '/';
      }
      fileName = 'whois.vp';
      type = UrlType.whois;
      // isWhois = true;
    } else {
      type = UrlType.didDoc;
    }

    return WebvhUrlX._(
      type: type,
      didUrl: url,
      scid: scid,
      domain: domain,
      port: port,
      path: path,
      fragment: fragment,
      query: query,
      fileName: fileName,
      queryVersionId: queryVersionId,
      queryVersionTime: queryVersionTime,
      queryVersionNumber: queryVersionNumber,
    );
  }

  static WebvhUrlX parseUrl(Uri uri) {
    if (uri.scheme != 'http' && uri.scheme != 'https') {
      throw SsiException(
          message: 'Invalid URL: Must be http or https',
          code: SsiExceptionType.invalidDidWebVh.code);
    }

    final fragment = uri.fragment.isEmpty ? null : uri.fragment;
    final (queryVersionId, queryVersionTime, queryVersionNumber) =
        _parseQuery(uri.query.isEmpty ? null : uri.query);

    final domain = uri.host;
    if (domain.isEmpty) {
      throw SsiException(
          message: 'Invalid URL: Must contain domain',
          code: SsiExceptionType.invalidDidWebVh.code);
    }

    final port = uri.hasPort ? uri.port : null;

    UrlType type;
    String path;
    String? fileName;

    if (uri.path == '/') {
      type = UrlType.didDoc;
      path = '/.well-known/';
      fileName = 'did.jsonl';
    } else if (uri.path.endsWith('/whois')) {
      type = UrlType.whois;
      path = '/whois.vp';
      fileName = null;
    } else if (uri.path.endsWith('/did.jsonl')) {
      type = UrlType.didDoc;
      path = uri.path.replaceAll('did.jsonl', '');
      fileName = 'did.jsonl';
    } else {
      type = UrlType.didDoc;
      path = uri.path.endsWith('/') ? uri.path : '${uri.path}/';
      fileName = 'did.jsonl';
    }

    return WebvhUrlX._(
      type: type,
      didUrl: uri.toString(),
      scid: '{SCID}',
      domain: domain,
      port: port,
      path: path,
      fragment: fragment,
      query: uri.query.isEmpty ? null : uri.query,
      fileName: fileName,
      queryVersionId: queryVersionId,
      queryVersionTime: queryVersionTime,
      queryVersionNumber: queryVersionNumber,
    );
  }

  static (String?, DateTime?, int?) _parseQuery(String? query) {
    if (query == null || query.isEmpty) {
      return (null, null, null);
    }

    String? versionId;
    DateTime? versionTime;
    int? versionNumber;

    for (final parameter in query.split('&')) {
      final equalsIndex = parameter.indexOf('=');
      if (equalsIndex == -1) {
        throw SsiException(
            message:
                'DID Query parameter ($parameter) is invalid. Must be in the format key=value.',
            code: SsiExceptionType.invalidDidWebVh.code);
      }

      final key = parameter.substring(0, equalsIndex);
      final value = parameter.substring(equalsIndex + 1);

      switch (key) {
        case 'versionId':
          versionId = value;
        case 'versionTime':
          versionTime = DateTime.tryParse(value);
          if (versionTime == null) {
            throw SsiException(
                message:
                    'DID Query parameter (versionTime) is invalid. Must be RFC 3339 compliant: $value',
                code: SsiExceptionType.invalidDidWebVh.code);
          }
        case 'versionNumber':
          versionNumber = int.tryParse(value);
          if (versionNumber == null) {
            throw SsiException(
                message:
                    'DID Query parameter (versionNumber) is invalid. Must be a positive integer: $value',
                code: SsiExceptionType.invalidDidWebVh.code);
          }
      }
    }

    return (versionId, versionTime, versionNumber);
  }

  String _getHttpBaseUrl() {
    final buffer = StringBuffer();

    if (domain == 'localhost') {
      buffer.write('http://');
    } else {
      buffer.write('https://');
    }

    buffer.write(domain);

    if (port != null) {
      buffer.write(':$port');
    }

    return buffer.toString();
  }

  Uri getHttpUrl({String? fileName}) {
    final buffer = StringBuffer(_getHttpBaseUrl());
    buffer.write(path);

    final effectiveFileName = fileName ?? this.fileName;
    if (effectiveFileName != null) {
      buffer.write(effectiveFileName);
    }

    if (query != null) {
      buffer.write('?$query');
    }

    if (fragment != null) {
      buffer.write('#$fragment');
    }

    return Uri.parse(buffer.toString());
  }

  Uri getHttpWhoisUrl() {
    final buffer = StringBuffer(_getHttpBaseUrl());

    if (path == '/.well-known/') {
      buffer.write('/whois.vp');
    } else {
      buffer.write(path);
      buffer.write('whois.vp');
    }

    return Uri.parse(buffer.toString());
  }

  Uri getHttpFilesUrl() {
    final buffer = StringBuffer(_getHttpBaseUrl());

    if (path == '/.well-known/') {
      buffer.write('/');
    } else {
      buffer.write(path);
    }

    return Uri.parse(buffer.toString());
  }

  @override
  String toString() {
    final buffer = StringBuffer('did:webvh:');
    buffer.write(scid);
    buffer.write(':');
    buffer.write(domain);

    if (port != null) {
      buffer.write('%3A$port');
    }
    if (path != '/.well-known/') {
      final pathWithoutSlashes = path.replaceAll('/', ':');
      buffer.write(pathWithoutSlashes.substring(
          0, pathWithoutSlashes.length - 1)); // Remove trailing :
    }
    if (query != null) {
      buffer.write('?$query');
    }
    if (fragment != null) {
      buffer.write('#$fragment');
    }
    return buffer.toString();
  }
}
