library cryptorio;

import 'dart:convert';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart';
import 'package:crypto/crypto.dart';

export 'package:encrypt/encrypt.dart' show IV;

/// A simple encryption/decryption helper using a password.
class Cryptorio {
  String _password = "";

  /// Creates a new instance of [Cryptorio] with the specified password.
  Cryptorio(String password) {
    _password = password;
  }

  /// Generates a key from the password using SHA-256.
  Key get key => Key(Uint8List.fromList(sha256.convert(utf8.encode(_password)).bytes));

  /// Encrypts a given [content] string using the password.
  ///
  /// Returns a Base64 encoded string that contains the IV and the encrypted content.
  String encrypt(String content, {IV? iv}) {
    final vector = iv ?? IV.fromLength(16);
    final encryptor = Encrypter(AES(key));
    final encrypted = encryptor.encrypt(content, iv: vector);
    return "${base64Url.encode(vector.bytes)}:${encrypted.base64}";
  }

  /// Decrypts a previously [encrypted] string using the password.
  ///
  /// Optionally, an [iv] function can be provided to customize IV extraction.
  ///
  /// Throws an [Exception] if the decryption fails due to an incorrect password or corrupted content.
  String decrypt(String encrypted, {IV Function(String)? iv}) {
    try {
      final parts = encrypted.split(":");
      final vector = iv?.call(parts[0]) ?? IV.fromBase64(parts[0]);
      final encryptor = Encrypter(AES(key));
      final decrypted = encryptor.decrypt64(parts[1], iv: vector);
      return decrypted;
    } catch(_) {
      throw Exception("The encrypted content is not matched with the password!");
    }
  }
}
