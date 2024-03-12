package ru.namerpro.cryptography.context.encrypter;

public enum Encrypter {
    DES(8);

    private final int blockSize;

    Encrypter(int blockSize) {
        this.blockSize = blockSize;
    }

    public int getBlockSize() {
        return blockSize;
    }

}
