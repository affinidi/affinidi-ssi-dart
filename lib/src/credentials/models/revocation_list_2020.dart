import '../../../ssi.dart';
import '../../util/json_util.dart';

/// Represents the credentialStatus entry of type RevocationList2020Status.
class RevocationList2020Status
    implements CredentialStatusV1, CredentialStatusV2 {
  @override
  final Uri id;

  @override
  final String type;

  final String revocationListIndex;
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
  dynamic operator [](Object? key) => throw UnimplementedError();

  @override
  void operator []=(String key, dynamic value) {}

  @override
  void addAll(Map<String, dynamic> other) {}

  @override
  void addEntries(Iterable<MapEntry<String, dynamic>> entries) {}

  @override
  Map<RK, RV> cast<RK, RV>() => throw UnimplementedError();

  @override
  void clear() {}

  @override
  bool containsKey(Object? key) => throw UnimplementedError();

  @override
  bool containsValue(Object? value) => throw UnimplementedError();

  @override
  Iterable<MapEntry<String, dynamic>> get entries => throw UnimplementedError();

  @override
  void forEach(void Function(String key, dynamic value) action) {}

  @override
  bool get isEmpty => throw UnimplementedError();

  @override
  bool get isNotEmpty => throw UnimplementedError();

  @override
  Iterable<String> get keys => throw UnimplementedError();

  @override
  int get length => throw UnimplementedError();

  @override
  Map<K2, V2> map<K2, V2>(
    MapEntry<K2, V2> Function(String key, dynamic value) transform,
  ) =>
      throw UnimplementedError();

  @override
  dynamic putIfAbsent(String key, dynamic Function() ifAbsent) =>
      throw UnimplementedError();

  @override
  dynamic remove(Object? key) => throw UnimplementedError();

  @override
  void removeWhere(bool Function(String key, dynamic value) test) {}

  @override
  dynamic update(
    String key,
    dynamic Function(dynamic value) update, {
    dynamic Function()? ifAbsent,
  }) =>
      throw UnimplementedError();

  @override
  void updateAll(dynamic Function(String key, dynamic value) update) {}

  @override
  Iterable<dynamic> get values => throw UnimplementedError();
}
