import '../exceptions/ssi_exception.dart';
import '../exceptions/ssi_exception_type.dart';

/// Represents a JSON-LD context.
class Context {
  /// The list of contexts.
  final List<dynamic> _contexts;

  /// Creates a [Context] instance.
  Context._(this._contexts);

  /// Creates a [Context] instance from a JSON input.
  ///
  /// [json] - The JSON input, which can be a string or a list.
  ///
  /// Throws an [SsiException] if the input is null or unsupported.
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

  /// Converts this context to a JSON-serializable object.
  dynamic toJson() {
    if (_contexts.length == 1) {
      return _contexts.first;
    }
    return _contexts;
  }

  /// Checks if the context contains the given URL.
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
