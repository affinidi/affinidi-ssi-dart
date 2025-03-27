/// A generic class representing an action that takes an input of type [T]
/// and produces an output of type [V]. Implementing classes should define the
/// logic for `execute(T input)`, where the input is processed to generate a result.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// Parameters:
/// - **[T]**: The type of input required by the action.
/// - **[V]**: The type of output produced by the action.
abstract class Action<T, V> {
  /// Executes the action with the given [input] and returns a result of type [V].
  ///
  /// Parameters:
  /// - **[input]**: The input data required to perform the action.
  V execute(T input);
}
