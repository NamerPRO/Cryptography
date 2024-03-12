package ru.namerpro.cryptography.api;

public interface EncryptMode {

    byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter);

    byte[] reverse(byte[] src, int blockSize, SymmetricEncrypter encrypter);

}
