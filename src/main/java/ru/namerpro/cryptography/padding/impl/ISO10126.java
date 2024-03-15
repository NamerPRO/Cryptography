package ru.namerpro.cryptography.padding.impl;

import ru.namerpro.cryptography.api.PaddingMode;

public class ISO10126 extends PaddingMode {

    @Override
    public byte[] add(byte[] src, int blockSize) {
        int toAddCount = blockSize - src.length % blockSize;
        byte[] out = new byte[src.length + toAddCount];
        System.arraycopy(src, 0, out, 0, src.length);
        for (int i = 0; i < toAddCount - 1; ++i) {
            out[src.length + i] = (byte) ((int) (Math.random() * 255) - 128);
        }
        out[out.length - 1] = (byte) toAddCount;
        return out;
    }

}
