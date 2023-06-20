/*
 * Copyright (c) TIKI Inc.
 * MIT license. See LICENSE file in root directory.
 */

class KeyModel {
  bool public;
  String key;

  KeyModel(this.key, {this.public = false});

  KeyModel.fromMap(Map<String, dynamic> map)
      : public = map['public'],
        key = map['key'];

  Map<String, dynamic> toMap() => {'public': public, 'key': key};
}
