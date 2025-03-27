import 'dart:convert';

import 'package:jose_plus/jose.dart';
import 'package:meta/meta.dart';
import 'package:sdjwt_sdk/sdjwt_sdk.dart';
import 'package:sdjwt_sdk/src/base/action.dart';
import 'package:sdjwt_sdk/src/models/disclosure_map.dart';
import 'package:sdjwt_sdk/src/sign/jwt_signer_base.dart';
import 'package:sdjwt_sdk/src/sign/nonce_generator.dart';
import 'package:sdjwt_sdk/src/utils/common.dart';
// import 'package:sdjwt_sdk/src/sign/nonce_generator.dart';
import 'package:sdjwt_sdk/src/utils/unpack_disclosures.dart';
import 'package:sdjwt_sdk/src/verify/kb_verifier.dart';
import 'package:sdjwt_sdk/src/verify/jwt_verifier_base.dart';

import '../sign/claim_processing/claim_processor.dart';
import '../utils/cnf_extractor.dart';
import '../utils/kb_jwt/base64_digest_calculator.dart';
import '../validator/kb_signer_input_validator.dart';

part '../sign/kbjwt_signer.dart';
part '../sign/sdjwt_signer.dart';
part '../verify/sd_jwt_verifier.dart';
part 'sdjwt_status.dart';

/// Regular expression for validating SD-JWT format.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
final _sdJwtRegExp =
    RegExp(r'^([A-Za-z0-9_-]+\.){2}[A-Za-z0-9_-]+(~[A-Za-z0-9_=]+?)*~?$');

/// The separator character used between JWT and disclosures in an SD-JWT.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
const String disclosureSeparator = '~';

/// A class representing a Selective Disclosure JWT (SD-JWT).
///
/// SD-JWT is a format that allows the issuer to selectively disclose claims
/// to verifiers, giving the holder control over which information is shared.
@immutable
class SdJwt {
  /// The serialized string representation of the SD-JWT.
  final String serialized;

  /// The decoded payload of the JWT part.
  final Map<String, dynamic> payload;

  /// The headers for this sdJwt.
  final Map<String, dynamic> header;

  /// The complete set of claims after applying all disclosures.
  final Map<String, dynamic> claims;

  /// The parsed JWT object.
  final String jwsString;

  /// The Key Binding JWT (KB-JWT) part of the SD-JWT.
  final String? kbString;

  /// The [Hasher] used for the disclosures.
  final Hasher<String, String> hasher;

  /// A map of disclosures indexed by their digest values.
  final DisclosureMap _disclosuresDigestMap;

  /// A map of disclosures indexed by their JSON path in the claims.
  final Map<String, Disclosure> _disclosuresPathMap;

  /// Tracks the verification status of the sdJwt
  final SdJwtStatus _verified;

  /// get the set of all disclosures.
  Set<Disclosure> get disclosures => _disclosuresDigestMap.values.toSet();

  /// Returns the verification status.
  bool? get isVerified => _verified.isVerified;

  /// Private constructor, so that instances of SdJwt can only be created via one of the factory methods.
  SdJwt._({
    required this.serialized,
    required Map<String, dynamic> payload,
    required Map<String, dynamic> header,
    required DisclosureMap disclosuresDigestMap,
    required Map<String, Disclosure> disclosuresPathIndex,
    required Map<String, dynamic> claims,
    required this.jwsString,
    required this.hasher,
    this.kbString,
  })  : _disclosuresDigestMap = disclosuresDigestMap,
        payload = Map<String, dynamic>.unmodifiable(payload),
        header = Map<String, dynamic>.unmodifiable(header),
        _disclosuresPathMap =
            Map<String, Disclosure>.unmodifiable(disclosuresPathIndex),
        claims = Map<String, dynamic>.unmodifiable(claims),
        _verified =
            SdJwtStatus(hasKbJwt: kbString != null && kbString.isNotEmpty);

  /// Parses a serialized SD-JWT string into an [SdJwt] object.
  ///
  /// Parameters:
  /// - **[serialized]**: The serialized SD-JWT string to parse.
  ///
  /// Throws an exception if the format is invalid.
  factory SdJwt.parse(String serialized, {CustomHasher? customHasher}) {
    if (!_sdJwtRegExp.hasMatch(serialized)) {
      throw Exception("Invalid SD-JWT: not well formatted");
    }

    final parts = serialized.split(disclosureSeparator);
    if (parts.length < 2) {
      throw Exception("Invalid SD-JWT: expected minimum two parts");
    }
    final String issuerJwt = parts.first;
    final String? kbJwt = parts.last.isEmpty ? null : parts.last;
    parts.removeLast();

    late final List<String> disclosureParts;
    disclosureParts = parts.length > 1 ? parts.sublist(1) : <String>[];

    final Set<String> disclosureStrings = Set.of(disclosureParts);
    if (disclosureStrings.length != disclosureParts.length) {
      throw Exception(
          "Invalid SD-JWT: Disclosures cannot be duplicate in sd-jwt");
    }

    final jwt = JsonWebSignature.fromCompactSerialization(issuerJwt);
    final payload = fromEncodedBytes(jwt.data);

    final hasher = Base64EncodedOutputHasher(
        Hasher.fromString(payload['_sd_alg'], customHasher: customHasher));

    final disclosuresDigestIndex =
        DisclosureMap.parse(disclosureStrings, hasher);

    final UnpackedDisclosuresOutput resolved = unpackDisclosures(
      tokenPayload: payload,
      disclosuresDigestIndex: disclosuresDigestIndex,
      hasher: hasher,
    );

    final disclosuresPathIndex = resolved.disclosuresPathIndex;
    final claims = resolved.unpackedPayload;

    return SdJwt._(
      serialized: serialized,
      payload: payload,
      header: jwt.commonHeader.toJson(),
      disclosuresDigestMap: disclosuresDigestIndex,
      disclosuresPathIndex: disclosuresPathIndex,
      claims: claims,
      jwsString: issuerJwt,
      kbString: kbJwt,
      hasher: hasher,
    );
  }

  /// Private factory to construct a [SdJwt] from it's parts.
  ///
  /// Parameters:
  /// - **[jwsToken]**: The serialized JWS to use as the base.
  /// - **[disclosures]**: The set of disclosures to include.
  /// - **[payload]**: The claims within the JWS.
  /// - **[hasher]**: The [Hasher] to be used.
  ///
  /// Returns a new [SdJwt] instance.
  factory SdJwt._fromParts({
    required String jwsToken,
    required Set<Disclosure> disclosures,
    required Map<String, dynamic> payload,
    required Hasher<String, String> hasher,
  }) {
    final jws = JsonWebSignature.fromCompactSerialization(jwsToken);

    final DisclosureMap disclosuresDigestIndex =
        DisclosureMap.from(disclosures);

    final UnpackedDisclosuresOutput resolved = unpackDisclosures(
      tokenPayload: payload,
      disclosuresDigestIndex: disclosuresDigestIndex,
      hasher: hasher,
    );

    final Map<String, Disclosure> disclosuresPathIndex =
        resolved.disclosuresPathIndex;
    final claims = resolved.unpackedPayload;

    final serialized = '${[
      jwsToken,
      ...disclosures.map((e) => e.toString()).toList()..sort()
    ].join(disclosureSeparator)}~';

    return SdJwt._(
      serialized: serialized,
      payload: payload,
      header: jws.commonHeader.toJson(),
      disclosuresDigestMap: disclosuresDigestIndex,
      disclosuresPathIndex: disclosuresPathIndex,
      claims: claims,
      jwsString: jwsToken,
      hasher: hasher,
    );
  }

  /// Creates a new [SdJwt] from the given disclosures subset.
  ///
  /// Parameters:
  /// - **[disclosuresToKeep]**: The set of disclosures to include in the encoded output.
  ///
  /// Returns the new [SdJwt].
  ///
  /// Throws an exception if any of the specified disclosures in [disclosuresToKeep] are not found in [disclosures].
  SdJwt withDisclosures(Set<Disclosure> disclosuresToKeep) {
    if (disclosuresToKeep
        .any((element) => !_disclosuresDigestMap.containsKey(element.digest))) {
      throw Exception('Unidentified disclosures');
    }

    final derivedSdJwt = SdJwt._fromParts(
      jwsToken: jwsString,
      disclosures: disclosuresToKeep,
      payload: payload,
      hasher: hasher,
    );

    derivedSdJwt._verified._isJwsVerified = _verified.isJwsVerified;
    return derivedSdJwt;
  }

  /// Creates a [SdJwt] from the current [SdJwt] and a serialized [kbJwt].
  ///
  /// Parameters:
  /// - **[kbJwt]**: The KB-JWT string to attach.
  ///
  /// Returns a new [SdJwt] instance.
  ///
  /// Throws an [Exception] if the KB-JWT is empty.
  SdJwt withKbJwt(String kbJwt) {
    if (kbJwt.isEmpty) {
      throw Exception('KbJwt cannot be empty');
    }

    final derivedSdJwt = SdJwt._(
        serialized: "$serialized$kbJwt",
        payload: payload,
        header: header,
        disclosuresDigestMap: _disclosuresDigestMap,
        disclosuresPathIndex: _disclosuresPathMap,
        claims: claims,
        jwsString: jwsString,
        hasher: hasher,
        kbString: kbJwt);

    derivedSdJwt._verified._isJwsVerified = _verified.isJwsVerified;
    return derivedSdJwt;
  }

  /// get the disclosure at the given path.
  Disclosure? disclosureAtPath(String path) {
    return _disclosuresPathMap[path];
  }
}
