import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';

class Context {
  final List<dynamic> _contexts;

  Context._(this._contexts);

  factory Context.fromJson(dynamic json) {
    if (json == null) {
      throw SsiException(
        message: 'null context',
        code: SsiExceptionType.invalidDidDocument.code,
      );
    }

    List<dynamic> contexts;
    switch (json) {
      case String s:
        contexts = [s];

      case List l:
        contexts = l;

      default:
        throw SsiException(
          message: 'Parsing context as ${json.runtimeType} is not supported!',
          code: SsiExceptionType.invalidDidDocument.code,
        );
    }

    return Context._(contexts);
  }

  dynamic toJson() {
    if (_contexts.length == 1) {
      return _contexts.first;
    }
    return _contexts;
  }

  bool hasUrlContext(Uri url) {
    for (final c in _contexts) {
      var urlStr = url.toString();
      if (c is String && c == urlStr) {
        return true;
      }
    }
    return false;
  }
}
