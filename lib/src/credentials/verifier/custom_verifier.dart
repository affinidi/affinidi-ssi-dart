import 'package:ssi/ssi.dart';

abstract class CustomVerifier {
  Future<bool> verify(VerifiableCredential vc);
}
