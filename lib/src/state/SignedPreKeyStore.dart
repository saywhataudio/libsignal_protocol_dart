import 'dart:async';

import 'SignedPreKeyRecord.dart';

abstract class SignedPreKeyStore {
  FutureOr<SignedPreKeyRecord> loadSignedPreKey(int signedPreKeyId); //throws InvalidKeyIdException;

  FutureOr<List<SignedPreKeyRecord>> loadSignedPreKeys();

  FutureOr<void> storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record);

  FutureOr<bool> containsSignedPreKey(int signedPreKeyId);

  FutureOr<void> removeSignedPreKey(int signedPreKeyId);
}
