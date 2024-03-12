package ru.namerpro.cryptography.api;

public interface EncryptingConversion {

    byte[] runFeistelFunction(byte[] block, byte[] roundKey);

}
