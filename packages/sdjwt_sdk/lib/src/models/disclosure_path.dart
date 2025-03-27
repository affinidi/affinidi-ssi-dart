import 'package:meta/meta.dart';
import 'package:rfc_6901/rfc_6901.dart';

/// A class representing a pointer to a path within a SD-JWT claims.
///
/// Example:
/// ```dart
/// final rootPath = DisclosurePath.root();
/// final firstNamePath = rootPath.segment('firstName');
///
/// // When the Disclosure needs to be created with unknown path and later updated.
/// final unknownPath = DisclosurePath();
/// unknownPath.update(firstNamePath);
///
/// // the full path as a string
/// firstNamePath.path
///
/// ```
@immutable
class DisclosurePath {
  final Set<JsonPointer> _pathPointer = {};

  /// Constructor to create a DisclosurePath with unknown path
  DisclosurePath();

  /// Whether the path is yet to set
  bool get isEmpty => _pathPointer.isEmpty;

  /// Get the full path as a string
  String get path {
    if (isEmpty) return '';
    return _pathPointer.first.toString();
  }

  /// One time update of the path if it is not yet set.
  ///
  /// Parameters:
  /// - **[input]**: Update the path to the same path as the given [DisclosurePath].
  ///
  /// Throws exception if we try to update the path after it is already set.
  void updateOnce(DisclosurePath input) {
    if (_pathPointer.isNotEmpty) {
      if (_pathPointer.first.toString() != input.path) {
        throw Exception(
            'A disclosure cannot be reused at another path within the SdJwt');
      }
    } else {
      _pathPointer.add(input._pathPointer.first);
    }
  }

  /// Internally uses a JsonPointer to keep track of the paths
  DisclosurePath._withPointer(JsonPointer pointer) {
    _pathPointer.add(pointer);
  }

  /// Internally uses a JsonPointer to keep track of the paths
  factory DisclosurePath._withPath(String path) {
    return DisclosurePath._withPointer(JsonPointer(path));
  }

  /// Returns the path to the root of the claims
  DisclosurePath.root() {
    final rootPath = JsonPointer();
    _pathPointer.add(rootPath);
  }

  /// Returns a relative [DisclosurePath] for the given [name]
  ///
  /// Parameters:
  /// -**[name]**: the relative path
  ///
  /// Returns a new [DisclosurePath]
  DisclosurePath segment(String name) {
    if (isEmpty) return DisclosurePath._withPath(name);

    final newPointer = JsonPointerSegment(name, _pathPointer.first);
    return DisclosurePath._withPointer(newPointer);
  }
}
