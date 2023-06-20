/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'rsa_private_key.dart';
import 'rsa_public_key.dart';

typedef RsaKeyPair = AsymmetricKeyPair<RsaPublicKey, RsaPrivateKey>;

Uint8List encrypt(RsaPublicKey key, Uint8List plaintext) {
  final encryptor = OAEPEncoding(RSAEngine())
    ..init(true, PublicKeyParameter<RSAPublicKey>(key));
  return processInBlocks(encryptor, plaintext);
}

Uint8List decrypt(RsaPrivateKey key, Uint8List ciphertext) {
  final decryptor = OAEPEncoding(RSAEngine())
    ..init(false, PrivateKeyParameter<RSAPrivateKey>(key));
  return processInBlocks(decryptor, ciphertext);
}

Uint8List sign(RsaPrivateKey key, Uint8List message) {
  RSASigner signer = RSASigner(SHA256Digest(), '0609608648016503040201');
  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(key));
  RSASignature signature = signer.generateSignature(message);
  return signature.bytes;
}

bool verify(RsaPublicKey key, Uint8List message, Uint8List signature) {
  RSASignature rsaSignature = RSASignature(signature);
  final verifier = RSASigner(SHA256Digest(), '0609608648016503040201');
  verifier.init(false, PublicKeyParameter<RSAPublicKey>(key));
  try {
    return verifier.verifySignature(message, rsaSignature);
  } on ArgumentError {
    return false;
  }
}

FortunaRandom secureRandom() {
  var secureRandom = FortunaRandom();
  var random = Random.secure();
  final seeds = <int>[];
  for (int i = 0; i < 32; i++) {
    seeds.add(random.nextInt(255));
  }
  secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));
  return secureRandom;
}

Uint8List processInBlocks(AsymmetricBlockCipher engine, Uint8List input) {
  final numBlocks = input.length ~/ engine.inputBlockSize +
      ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

  final output = Uint8List(numBlocks * engine.outputBlockSize);

  var inputOffset = 0;
  var outputOffset = 0;
  while (inputOffset < input.length) {
    final chunkSize = (inputOffset + engine.inputBlockSize <= input.length)
        ? engine.inputBlockSize
        : input.length - inputOffset;

    outputOffset += engine.processBlock(
        input, inputOffset, chunkSize, output, outputOffset);

    inputOffset += chunkSize;
  }

  return (output.length == outputOffset)
      ? output
      : output.sublist(0, outputOffset);
}
