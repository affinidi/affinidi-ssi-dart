import 'dart:typed_data';

class Proof {
  String type = "";
  String cryptosuite = "";
  String created = "";
  String verificationMethod = "";
  String proofPurpose = "";
  String proofValue = "";
}

abstract class ProofGenerator {
  Proof generate(Uint8List digest) {
    return Proof();
  }
}
