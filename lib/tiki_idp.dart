/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

library tiki_idp;

import 'dart:typed_data';

import 'auth/JWT.dart';
import 'auth/auth_service.dart';
import 'key/key_platform.dart';
import 'key/key_service.dart';
import 'registry/registry.dart';
import 'registry/registry_service.dart';
import 'rsa/rsa.dart' as RSA;
import 'rsa/rsa_private_key.dart';

export 'auth/jwt.dart';
export 'key/key_platform.dart';
export 'registry/registry.dart';

class TikiIDP {
  final KeyService _keyService;
  final AuthService _authService;
  late final RegistryService _registryService;

  TikiIDP(
      String user, List<String> scope, String clientId, KeyPlatform platform,
      {String? clientSecret})
      : _keyService = KeyService(platform),
        _authService =
            AuthService(clientId, scope, clientSecret: clientSecret) {
    _registryService = RegistryService(_keyService, _authService);
  }

  Future<void> key(String id) async {
    RsaPrivateKey privateKey = await _keyService.generate();
    await _keyService.save(id, privateKey);
  }

  Future<Uint8List> sign(String key, Uint8List message) async {
    RsaPrivateKey? privateKey = await _keyService.get(key);
    if (privateKey == null) throw RangeError('Missing key: $key');
    return RSA.sign(privateKey, message);
  }

  Future<bool> verify(
      String key, Uint8List message, Uint8List signature) async {
    RsaPrivateKey? privateKey = await _keyService.get(key);
    if (privateKey == null) throw RangeError('Missing key: $key');
    return RSA.verify(privateKey.public, message, signature);
  }

  Future<Registry> register(String key, String user, String address) =>
      _registryService.register(user, address, key);

  Future<Registry> registry(String key, String user) =>
      _registryService.get(user, key);

  Future<JWT> get token => _authService.token;
}
