/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:tiki_idp/rsa/rsa.dart' as rsa;
import 'package:tiki_idp/rsa/rsa_private_key.dart';
import 'package:tiki_idp/rsa/rsa_public_key.dart';

rsa.KeyPair generate() {
  final keyGen = RSAKeyGenerator()
    ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64),
        rsa.secureRandom()));

  AsymmetricKeyPair<PublicKey, PrivateKey> keyPair = keyGen.generateKeyPair();
  RSAPublicKey publicKey = keyPair.publicKey as RSAPublicKey;
  RSAPrivateKey privateKey = keyPair.privateKey as RSAPrivateKey;

  return rsa.KeyPair(
      RsaPublicKey(publicKey.modulus!, publicKey.publicExponent!),
      RsaPrivateKey(privateKey.modulus!, privateKey.privateExponent!,
          privateKey.p, privateKey.q));
}
