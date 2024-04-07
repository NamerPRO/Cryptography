package ru.namerpro.cryptography.api.symmetric.modes;

import ru.namerpro.cryptography.api.symmetric.SymmetricEncrypter;

public interface SymmetricEncryptMode {

    byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter);

    byte[] reverse(byte[] src, int blockSize, SymmetricEncrypter encrypter);

}
