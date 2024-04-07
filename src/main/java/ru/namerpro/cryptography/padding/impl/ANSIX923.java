package ru.namerpro.cryptography.padding.impl;

import ru.namerpro.cryptography.api.symmetric.modes.SymmetricPaddingMode;

public class ANSIX923 extends SymmetricPaddingMode {

    @Override
    public byte[] add(byte[] src, int blockSize) {
        int toAddCount = blockSize - src.length % blockSize;
        byte[] out = new byte[src.length + toAddCount];
        System.arraycopy(src, 0, out, 0, src.length);
        out[out.length - 1] = (byte) toAddCount;
        return out;
    }

}
