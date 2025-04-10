abstract class DecodedType {}

abstract interface class VerifiableDataParser<SerializedType, DecodedType> {
  bool canDecode(SerializedType input);
  DecodedType decode(SerializedType input);
}
