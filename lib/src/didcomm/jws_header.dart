class JwsHeader {
  final String alg;
  final String crv;
  final String typ;

  JwsHeader({required this.alg, required this.crv, required this.typ});

  Map<String, dynamic> toJson() {
    return {
      'typ': typ,
      'alg': alg,
      'crv': crv,
    };
  }
}
