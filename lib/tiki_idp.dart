/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

library tiki_idp;

import 'dart:typed_data';

import 'auth/auth_service.dart';
import 'auth/jwt.dart';
import 'key/key_model.dart';
import 'key/key_platform.dart';
import 'key/key_service.dart';
import 'registry/registry.dart';
import 'registry/registry_service.dart';
import 'rsa/rsa.dart' as rsa;
import 'rsa/rsa_private_key.dart';
import 'rsa/rsa_public_key.dart';

export 'auth/jwt.dart';
export 'key/key_platform.dart';
export 'registry/registry.dart';

class TikiIdp {
  final KeyService _keyService;
  final AuthService _authService;
  late final RegistryService _registryService;

  TikiIdp(List<String> scope, String clientId, KeyPlatform platform,
      {String? clientSecret})
      : _keyService = KeyService(platform),
        _authService =
            AuthService(clientId, scope, clientSecret: clientSecret) {
    _registryService = RegistryService(_keyService, _authService);
  }

  Future<void> key(String keyId, {bool overwrite = false}) async {
    KeyModel? keyModel = await _keyService.get(keyId);
    if (keyModel == null || overwrite) {
      RsaPrivateKey privateKey = await _keyService.generate();
      await _keyService.save(keyId, KeyModel(privateKey.encode()));
    }
  }

  Future<String> export(String keyId, {bool public = true}) async {
    KeyModel? keyModel = await _keyService.get(keyId);
    if (keyModel == null) throw RangeError('Missing key: $keyId');
    if (!keyModel.public && public) {
      RsaPrivateKey privateKey = RsaPrivateKey.decode(keyModel.key);
      return privateKey.public.encode();
    } else if (keyModel.public && !public) {
      throw ArgumentError("Incompatible key: $keyId");
    } else {
      return keyModel.key;
    }
  }

  Future<void> import(String keyId, String key, {bool public = true}) =>
      _keyService.save(keyId, KeyModel(key, public: public));

  Future<Uint8List> sign(String keyId, Uint8List message) async {
    KeyModel? keyModel = await _keyService.get(keyId);
    if (keyModel == null) throw RangeError('Missing key: $keyId');
    if (keyModel.public) throw ArgumentError('Incompatible key: $keyId');
    RsaPrivateKey privateKey = RsaPrivateKey.decode(keyModel.key);
    return rsa.sign(privateKey, message);
  }

  Future<bool> verify(
      String keyId, Uint8List message, Uint8List signature) async {
    KeyModel? keyModel = await _keyService.get(keyId);
    if (keyModel == null) throw RangeError('Missing key: $keyModel');
    RsaPublicKey publicKey;
    if (keyModel.public) {
      publicKey = RsaPublicKey.decode(keyModel.key);
    } else {
      publicKey = RsaPrivateKey.decode(keyModel.key).public;
    }
    return rsa.verify(publicKey, message, signature);
  }

  Future<Registry> register(String user, String address,
          {String? token, String? keyId}) =>
      _registryService.register(user, address, keyId ?? user, token: token);

  Future<Registry> registry(String keyId, String user) =>
      _registryService.get(user, keyId);

  Future<JWT> get token => _authService.token;

  static String pkcs8(
          BigInt modulus, BigInt privateExponent, BigInt p, BigInt q) =>
      RsaPrivateKey(modulus, privateExponent, p, q).encode();

  static String pem(BigInt modulus, BigInt exponent) =>
      RsaPublicKey(modulus, exponent).encode();
}
