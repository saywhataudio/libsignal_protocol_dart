import 'dart:async';

import 'PreKeyRecord.dart';

abstract class PreKeyStore {
  FutureOr<PreKeyRecord> loadPreKey(int preKeyId); //  throws InvalidKeyIdException;

  FutureOr<void> storePreKey(int preKeyId, PreKeyRecord record);

  FutureOr<bool> containsPreKey(int preKeyId);

  FutureOr<void> removePreKey(int preKeyId);
}
