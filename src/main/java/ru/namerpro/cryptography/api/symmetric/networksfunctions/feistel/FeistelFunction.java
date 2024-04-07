package ru.namerpro.cryptography.api.symmetric.networksfunctions.feistel;

public interface FeistelFunction {

    byte[] runFeistelFunction(byte[] block, byte[] roundKey);

}
