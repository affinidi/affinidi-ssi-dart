/// A generic stack implementation that follows the Last-In-First-Out (LIFO) principle.
///
/// This class provides standard stack operations like push, pop, and peek.
///
/// @internal
/// This is an internal implementation detail, not intended for direct use by consumers of the package.
///
/// Type parameter:
/// - **[E]**: The type of elements stored in the stack.
class Stack<E> {
  /// The internal list used to store stack elements.
  late final List<E> _list;

  /// Creates a new stack, optionally initialized with elements from [source].
  ///
  /// Parameters:
  /// - **[source]**: An optional list of elements to initialize the stack with.
  Stack({List<E>? source}) {
    _list = List.from(source ?? <E>[]);
  }

  /// Pushes a value onto the top of the stack.
  ///
  /// Parameters:
  /// - **[value]**: The value to push onto the stack.
  void push(E value) => _list.add(value);

  /// Pushes all elements from another stack onto this stack.
  ///
  /// Parameters:
  /// - **[value]**: The stack whose elements should be pushed onto this stack.
  void pushAll(Stack<E> value) => _list.addAll(value._list);

  /// Removes and returns the top element from the stack.
  ///
  /// Returns the element that was at the top of the stack.
  E pop() => _list.removeLast();

  /// Removes all elements from the stack.
  void clear() => _list.clear();

  /// Checks if the stack is not empty.
  ///
  /// Returns true if the stack contains at least one element.
  bool get isNotEmpty => _list.isNotEmpty;
}
