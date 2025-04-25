import '../models/parsed_vc.dart';
import '../models/v1/vc_data_model_v1.dart';

abstract interface class LdVcDataModelV1
    implements ParsedVerifiableCredential<String>, VcDataModelV1 {}
