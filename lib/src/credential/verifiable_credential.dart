class UnsignedCredential {}

class VerifiableCredential extends UnsignedCredential {
  VerifiableCredential();

  factory VerifiableCredential.fromJson(dynamic data) {
    return VerifiableCredential();
  }
}
