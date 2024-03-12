package ru.namerpro.cryptography.api;

public interface SymmetricEncrypter {

    byte[] encrypt(byte[] block);

    byte[] decrypt(byte[] block);

}
