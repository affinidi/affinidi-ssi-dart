import '../../../ssi.dart';
import '../../util/json_util.dart';

class RevocationList2020Status
    implements CredentialStatusV1, CredentialStatusV2 {
  @override
  final Uri id;

  @override
  final String type;

  final String revocationListIndex;
  final String revocationListCredential;

  RevocationList2020Status(Map<String, dynamic> data)
      : id = getMandatoryUri(data, 'id'),
        type = getMandatoryString(data, 'type'),
        revocationListIndex = getMandatoryString(data, 'revocationListIndex'),
        revocationListCredential =
            getMandatoryString(data, 'revocationListCredential');

  factory RevocationList2020Status.fromJson(Map<String, dynamic> json) {
    return RevocationList2020Status(json);
  }

  Map<String, dynamic> toJson() => {
        'id': id.toString(),
        'type': type,
        'revocationListIndex': revocationListIndex,
        'revocationListCredential': revocationListCredential,
      };

  @override
  operator [](Object? key) {
    // TODO: implement []
    throw UnimplementedError();
  }

  @override
  void operator []=(String key, value) {
    // TODO: implement []=
  }

  @override
  void addAll(Map<String, dynamic> other) {
    // TODO: implement addAll
  }

  @override
  void addEntries(Iterable<MapEntry<String, dynamic>> entries) {
    // TODO: implement addEntries
  }

  @override
  Map<RK, RV> cast<RK, RV>() {
    // TODO: implement cast
    throw UnimplementedError();
  }

  @override
  void clear() {
    // TODO: implement clear
  }

  @override
  bool containsKey(Object? key) {
    // TODO: implement containsKey
    throw UnimplementedError();
  }

  @override
  bool containsValue(Object? value) {
    // TODO: implement containsValue
    throw UnimplementedError();
  }

  @override
  // TODO: implement entries
  Iterable<MapEntry<String, dynamic>> get entries => throw UnimplementedError();

  @override
  void forEach(void Function(String key, dynamic value) action) {
    // TODO: implement forEach
  }

  @override
  // TODO: implement isEmpty
  bool get isEmpty => throw UnimplementedError();

  @override
  // TODO: implement isNotEmpty
  bool get isNotEmpty => throw UnimplementedError();

  @override
  // TODO: implement keys
  Iterable<String> get keys => throw UnimplementedError();

  @override
  // TODO: implement length
  int get length => throw UnimplementedError();

  @override
  Map<K2, V2> map<K2, V2>(
      MapEntry<K2, V2> Function(String key, dynamic value) transform) {
    // TODO: implement map
    throw UnimplementedError();
  }

  @override
  putIfAbsent(String key, Function() ifAbsent) {
    // TODO: implement putIfAbsent
    throw UnimplementedError();
  }

  @override
  remove(Object? key) {
    // TODO: implement remove
    throw UnimplementedError();
  }

  @override
  void removeWhere(bool Function(String key, dynamic value) test) {
    // TODO: implement removeWhere
  }

  @override
  update(String key, Function(dynamic value) update, {Function()? ifAbsent}) {
    // TODO: implement update
    throw UnimplementedError();
  }

  @override
  void updateAll(Function(String key, dynamic value) update) {
    // TODO: implement updateAll
  }

  @override
  // TODO: implement values
  Iterable get values => throw UnimplementedError();
}
