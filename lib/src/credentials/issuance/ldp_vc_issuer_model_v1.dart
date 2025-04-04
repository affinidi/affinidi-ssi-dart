import 'package:json_ld_processor/json_ld_processor.dart';

import '../../did/did_signer.dart';
import '../models/vc_data_model_v1.dart';
import 'dart:convert';

class LdpVcdm1Issuer {
  static Future<VcDataModelV1> issue({
    required VcDataModelV1 unsignedCredential,
    required DidSigner signer,
  }) async {
    unsignedCredential.issuer = signer.did;

    print(jsonEncode(unsignedCredential.toJson()));

    final normal = await JsonLdProcessor.normalize(
      unsignedCredential.toJson(),
      options: JsonLdOptions(
        safeMode: true,
        documentLoader: loadDocument,
      ),
    );

    print(normal);
    //
    // final signature = await signer.sign(utf8.encode(normal));
    //
    // print(base64UrlEncode(signature));

    return unsignedCredential;
  }
}
