/// Base type for decoded verifiable data.
abstract class DecodedType {}

/// Interface for parsers that decode serialized verifiable data.
///
/// Implementations of this interface provide methods to check if data can be
/// decoded and to perform the actual decoding of verifiable credentials or
/// presentations from their serialized formats.
abstract interface class VerifiableDataParser<SerializedType, DecodedType> {
  /// Determines whether the [input] can be decoded by this parser.
  bool canDecode(SerializedType input);

  /// Decodes the [input] into the appropriate data type.
  ///
  /// Throws an exception if the input cannot be properly decoded.
  DecodedType decode(SerializedType input);

  /// Attempts to decode the [input] and returns the result if successful, null otherwise.
  ///
  /// This method combines validation and parsing in one step to avoid redundant operations.
  DecodedType? tryDecode(SerializedType input);
}
