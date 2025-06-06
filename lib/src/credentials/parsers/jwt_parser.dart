import 'dart:convert';
import 'dart:developer' as developer;

import '../../exceptions/ssi_exception.dart';
import '../../exceptions/ssi_exception_type.dart';
import '../../util/base64_util.dart';
import 'verifiable_data_parser.dart';

/// Represents a decoded JSON Web Signature.
///
/// Contains the parsed components of a JWS: header, payload, and signature,
/// along with the original serialized form.
class Jws {
  /// The decoded JWS header containing metadata about the signature.
  Map<String, dynamic> header;

  /// The decoded JWS payload containing the actual data.
  Map<String, dynamic> payload;

  /// The base64url-encoded signature.
  String signature;

  /// The original serialized JWS string.
  String serialized;

  /// Creates a new [Jws] instance with the provided components.
  Jws(
      {required this.header,
      required this.payload,
      required this.signature,
      required this.serialized});
}

/// Mixin that provides functionality for parsing JWT/JWS formatted data.
///
/// Implements the [VerifiableDataParser] interface for JWS tokens,
/// providing methods to check if a string is a valid JWT and to decode
/// it into its component parts.
mixin JwtParser implements VerifiableDataParser<String, Jws> {
  @override
  bool canDecode(String input) {
    return input.startsWith('ey') &&
        input.split('.').length == 3 &&
        input.split('~').length == 1;
  }

  @override
  Jws decode(String input) {
    final segments = input.split('.');

    if (segments.length != 3) {
      throw SsiException(
        message: 'Invalid JWT',
        code: SsiExceptionType.invalidVC.code,
      );
    }

    final header = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(segments[0]),
      ),
    ) as Map<String, dynamic>;

    final payload = jsonDecode(
      utf8.decode(
        base64UrlNoPadDecode(segments[1]),
      ),
    ) as Map<String, dynamic>;

    return Jws(
        header: header,
        payload: payload,
        signature: segments[2],
        serialized: input);
  }

  @override
  Jws? tryDecode(String input) {
    if (!canDecode(input)) {
      return null;
    }

    try {
      return decode(input);
    } catch (e) {
      developer.log(
        'JWT decode failed',
        level: 500, // FINE
        error: e,
      );
      return null;
    }
  }
}
