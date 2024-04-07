package ru.namerpro.cryptography.padding.impl;

import ru.namerpro.cryptography.api.symmetric.modes.PaddingMode;

public class PKCS7 extends PaddingMode {

    @Override
    public byte[] add(byte[] src, int blockSize) {
        int toAddCount = blockSize - src.length % blockSize;
        byte[] out = new byte[src.length + toAddCount];
        System.arraycopy(src, 0, out, 0, src.length);
        for (int i = 0; i < toAddCount; ++i) {
            out[src.length + i] = (byte) toAddCount;
        }
        return out;
    }

}
