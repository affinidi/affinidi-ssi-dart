import 'dart:collection';

import '../../../ssi.dart';
import '../../util/json_util.dart';

/// Represents the credentialStatus entry of type RevocationList2020Status.
class RevocationList2020Status extends MapBase<String, dynamic>
    implements CredentialStatusV1, CredentialStatusV2 {
  @override
  final Uri id;

  @override
  final String type;

  /// The index in the status bitstring representing this credential.
  final String revocationListIndex;

  /// The URI to the Verifiable Credential that contains the revocation bitstring.
  final String revocationListCredential;

  /// Constructs from a raw JSON-like map.
  RevocationList2020Status(Map<String, dynamic> data)
      : id = getMandatoryUri(data, 'id'),
        type = getMandatoryString(data, 'type'),
        revocationListIndex = getMandatoryString(data, 'revocationListIndex'),
        revocationListCredential =
            getMandatoryString(data, 'revocationListCredential');

  /// Constructs from a JSON object.
  factory RevocationList2020Status.fromJson(Map<String, dynamic> json) {
    return RevocationList2020Status(json);
  }

  @override
  Map<String, dynamic> toJson() => {
        'id': id.toString(),
        'type': type,
        'revocationListIndex': revocationListIndex,
        'revocationListCredential': revocationListCredential,
      };

  @override
  dynamic operator [](Object? key) {
    if (key is String) {
      switch (key) {
        case 'id':
          return id;
        case 'type':
          return type;
        case 'revocationListIndex':
          return revocationListIndex;
        case 'revocationListCredential':
          return revocationListCredential;
      }
    }
    return null;
  }

  @override
  void operator []=(String key, dynamic value) {
    throw UnsupportedError('RevocationList2020Status is immutable');
  }

  @override
  void clear() {
    throw UnsupportedError('RevocationList2020Status is immutable');
  }

  @override
  Iterable<String> get keys => [
        'id',
        'type',
        'revocationListIndex',
        'revocationListCredential',
      ];

  @override
  dynamic remove(Object? key) {
    throw UnsupportedError('RevocationList2020Status is immutable');
  }
}
