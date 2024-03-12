package ru.namerpro.cryptography.api;

public abstract class PaddingMode {

    public abstract byte[] add(byte[] src, int blockSize);

    public byte[] remove(byte[] src, int blockSize) {
        int toRemoveCount = src[src.length - 1];
        byte[] out = new byte[src.length - toRemoveCount];
        System.arraycopy(src, 0, out, 0, src.length - toRemoveCount);
        return out;
    }

}
