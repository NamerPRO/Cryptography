package ru.namerpro.cryptography.padding.impl;

import ru.namerpro.cryptography.api.symmetric.modes.SymmetricPaddingMode;

public class Zeros extends SymmetricPaddingMode {

    @Override
    public byte[] add(byte[] src, int blockSize) {
        if (src.length % blockSize == 0) {
            return src;
        }
        int toAddCount = blockSize - src.length % blockSize;
        byte[] out = new byte[src.length + toAddCount];
        System.arraycopy(src, 0, out, 0, src.length);
        return out;
    }

    @Override
    public byte[] remove(byte[] src, int blockSize) {
        int barrier = src.length;
        while (barrier > 0 && src[barrier - 1] == 0) {
            --barrier;
        }
        byte[] out = new byte[barrier];
        System.arraycopy(src, 0, out, 0, barrier);
        return out;
    }

}
