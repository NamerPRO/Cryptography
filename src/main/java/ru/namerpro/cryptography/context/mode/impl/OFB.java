package ru.namerpro.cryptography.context.mode.impl;

import lombok.RequiredArgsConstructor;
import ru.namerpro.cryptography.Utils.Utility;
import ru.namerpro.cryptography.api.EncryptMode;
import ru.namerpro.cryptography.api.SymmetricEncrypter;

@RequiredArgsConstructor
public class OFB implements EncryptMode {

    private final byte[] iv;

    @Override
    public byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        byte[][] o = preprocess(split.length, encrypter);
        byte[] c = new byte[src.length];
        byte[] block;
        for (int i = 0; i < split.length; ++i) {
            block = Utility.xor(split[i], o[i]);
            for (int j = 0; j < blockSize; ++j) {
                c[blockSize * i + j] = block[j];
            }
        }
        return c;
    }

    @Override
    public byte[] reverse(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        byte[][] o = preprocess(split.length, encrypter);
        byte[] m = new byte[src.length];
        byte[] block;
        for (int i = 0; i < split.length; ++i) {
            block = Utility.xor(split[i], o[i]);
            for (int j = 0; j < blockSize; ++j) {
                m[blockSize * i + j] = block[j];
            }
        }
        return m;
    }

    private byte[][] preprocess(int blocksCount, SymmetricEncrypter encrypter) {
        byte[][] o = new byte[blocksCount][];
        for (int i = 0; i < blocksCount; ++i) {
            o[i] = encrypter.encrypt(i == 0 ? iv : o[i - 1]);
        }
        return o;
    }

}
