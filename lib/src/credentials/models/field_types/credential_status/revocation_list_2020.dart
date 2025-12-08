import 'dart:collection';

import '../../../../../ssi.dart';
import '../../../../util/json_util.dart';

/// Shared interface for both mutable and immutable RevocationList2020Status.
abstract interface class _RevocationList2020StatusInterface
    extends UnmodifiableMapBase<String, dynamic> {
  Uri? get id;
  String? get type;
  String? get revocationListIndex;
  String? get revocationListCredential;

  @override
  Iterable<String> get keys => const [
        'id',
        'type',
        'revocationListIndex',
        'revocationListCredential',
      ];

  Map<String, dynamic> toJson() {
    return cleanEmpty({
      'id': id?.toString(),
      'type': type,
      'revocationListIndex': revocationListIndex,
      'revocationListCredential': revocationListCredential,
    });
  }
}

/// Mutable representation of RevocationList2020Status for Verifiable Credentials.
class MutableRevocationList2020Status extends _RevocationList2020StatusInterface
    implements MutableCredentialStatusV1, MutableCredentialStatusV2 {
  @override
  Uri? id;

  @override
  String? type;

  @override
  String? revocationListIndex;

  @override
  String? revocationListCredential;

  /// Constructs mutable instance.
  MutableRevocationList2020Status({
    this.id,
    this.type,
    this.revocationListIndex,
    this.revocationListCredential,
  });

  /// Constructs from a JSON map.
  factory MutableRevocationList2020Status.fromJson(Map<String, dynamic> json) {
    return MutableRevocationList2020Status(
      id: getUri(json, 'id'),
      type: getString(json, 'type'),
      revocationListIndex: getStringOrNumber(json, 'revocationListIndex'),
      revocationListCredential: getString(json, 'revocationListCredential'),
    );
  }

  @override
  dynamic operator [](Object? key) {
    switch (key) {
      case 'id':
        return id;
      case 'type':
        return type;
      case 'revocationListIndex':
        return revocationListIndex;
      case 'revocationListCredential':
        return revocationListCredential;
      default:
        return null;
    }
  }

  @override
  void operator []=(String key, dynamic value) {
    switch (key) {
      case 'id':
        id = getUri({'id': value}, 'id');
        break;
      case 'type':
        type = getString({'type': value}, 'type');
        break;
      case 'revocationListIndex':
        revocationListIndex = value?.toString();
        break;
      case 'revocationListCredential':
        revocationListCredential = value?.toString();
        break;
    }
  }

  @override
  void clear() {
    id = null;
    type = null;
    revocationListIndex = null;
    revocationListCredential = null;
  }

  @override
  dynamic remove(Object? key) {
    switch (key) {
      case 'id':
        final oldId = id;
        id = null;
        return oldId;
      case 'type':
        final oldType = type;
        type = 'RevocationList2020Status';
        return oldType;
      case 'revocationListIndex':
        final oldIndex = revocationListIndex;
        revocationListIndex = null;
        return oldIndex;
      case 'revocationListCredential':
        final oldCredential = revocationListCredential;
        revocationListCredential = null;
        return oldCredential;
      default:
        return null;
    }
  }
}

/// Immutable representation of RevocationList2020Status.
class RevocationList2020Status extends _RevocationList2020StatusInterface
    implements CredentialStatusV1, CredentialStatusV2 {
  @override
  final Uri id;

  @override
  final String type;

  /// The index in the status bitstring representing this credential.
  @override
  final String revocationListIndex;

  /// The URI to the Verifiable Credential that contains the revocation bitstring.
  @override
  final String revocationListCredential;

  /// Constructs RevocationList2020Status
  RevocationList2020Status(
      {required this.id,
      required this.type,
      required this.revocationListIndex,
      required this.revocationListCredential});

  /// Constructs from a JSON object.
  factory RevocationList2020Status.fromJson(Map<String, dynamic> json) {
    final id = getMandatoryUri(json, 'id');
    final type = getMandatoryString(json, 'type');
    final revocationListIndex =
        getMandatoryStringOrNumber(json, 'revocationListIndex');
    final revocationListCredential =
        getMandatoryString(json, 'revocationListCredential');
    return RevocationList2020Status(
        id: id,
        type: type,
        revocationListIndex: revocationListIndex,
        revocationListCredential: revocationListCredential);
  }

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
}
