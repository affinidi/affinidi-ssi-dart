import 'dart:convert';

import 'package:meta/meta.dart';
import 'package:sdjwt_sdk/src/models/disclosure_path.dart';

import '../base/hasher.dart';

/// A class representing a disclosure in an SD-JWT. The class also provides some
/// disclosure functionalities like parsing, decoding and encoding.
///
/// Example:
/// ```dart
/// final disclosure = Disclosure(
///   salt: "random-salt",
///   claimName: "email",
///   claimValue: "alice@example.com",
///   hasher: Base64EncodedOutputHasher.base64Sha256,
///   serialized: "serializedString",
///   digest: "digestValue",
/// );
///
/// ```
@immutable
class Disclosure {
  /// A unique salt string value.
  final String salt;

  /// Optional string claim name, or key.
  final String? claimName;

  /// The value can be of any type that is allowed in JSON, including numbers,
  /// strings, booleans, arrays, null, and objects.
  final dynamic claimValue;

  /// The [Hasher] used to compute the disclosure digest.
  final Hasher<String, String> hasher;

  /// The serialized encoded disclosure.
  final String serialized;

  /// The digest (hash) of the disclosure
  final String digest;

  /// the specific location in the claims where this disclosure appears.
  final DisclosurePath _pathPointer = DisclosurePath();

  /// The pointer to the location within the claims where this disclosure appears.
  DisclosurePath get pointer => _pathPointer;
  set pointer(DisclosurePath input) => _pathPointer.updateOnce(input);

  /// Creates a disclosure object with the specified [salt], [claimName], [claimValue] and [hasher].
  Disclosure._(
      {required this.salt,
      this.claimName,
      required this.claimValue,
      required this.hasher,
      required this.serialized,
      required this.digest});

  /// Calculates the disclosure's [serialized] and [digest] values.
  factory Disclosure.from(
      {required String salt,
      String? claimName,
      required dynamic claimValue,
      required Hasher<String, String> hasher,
      String? serialized}) {
    final disclosureArray =
        claimName != null ? [salt, claimName, claimValue] : [salt, claimValue];
    if (serialized == null || serialized.isEmpty) {
      serialized = encode(disclosureArray);
    }

    final digest = hasher.execute(serialized);

    return Disclosure._(
        salt: salt,
        claimName: claimName,
        claimValue: claimValue,
        hasher: hasher,
        serialized: serialized,
        digest: digest);
  }

  /// Factory method to parse the base64-encoded disclosure string into a [Disclosure].
  factory Disclosure.parse(
    String encodedDisclosure,
    Hasher<String, String> hasher,
  ) {
    final decodedJson = decode(encodedDisclosure);

    if (decodedJson.length == 3) {
      return Disclosure.from(
          salt: decodedJson[0] as String,
          claimName: decodedJson[1] as String,
          claimValue: decodedJson[2],
          hasher: hasher,
          serialized: encodedDisclosure);
    } else if (decodedJson.length == 2) {
      return Disclosure.from(
          salt: decodedJson[0] as String,
          claimValue: decodedJson[1],
          hasher: hasher,
          serialized: encodedDisclosure);
    }

    throw FormatException('Invalid disclosure format');
  }

  @override
  String toString() {
    return serialized;
  }

  /// Decodes the base64-encoded disclosure string into its JSON representation.
  static List<dynamic> decode(String encodedDisclosure) {
    try {
      final n = base64Url.normalize(encodedDisclosure);
      final d = base64Url.decode(n);
      final u = utf8.decode(d);
      return json.decode(u);
    } catch (e) {
      throw FormatException('Error decoding disclosure: $e');
    }
  }

  /// Encodes a disclosure JSON into a base64-encoded disclosure string.
  static String encode(List<dynamic> disclosureArray) {
    return base64UrlEncode(utf8.encode(jsonEncode(disclosureArray)));
  }
}
