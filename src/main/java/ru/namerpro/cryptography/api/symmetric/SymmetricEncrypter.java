package ru.namerpro.cryptography.api.symmetric;

public interface SymmetricEncrypter {

    byte[] encrypt(byte[] block);

    byte[] decrypt(byte[] block);

}
