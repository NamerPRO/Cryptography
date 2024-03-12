package ru.namerpro.cryptography.context.mode.impl;

import lombok.RequiredArgsConstructor;
import ru.namerpro.cryptography.Utils.Pair;
import ru.namerpro.cryptography.Utils.Utility;
import ru.namerpro.cryptography.api.EncryptMode;
import ru.namerpro.cryptography.api.SymmetricEncrypter;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

public class CTR implements EncryptMode {

    private final ExecutorService service;
    private final byte[] iv;
    private final int blockSize;

    public CTR(ExecutorService service, byte[] iv, int blockSize) {
        this.service = service;

        if (blockSize <= iv.length) {
            throw new IllegalArgumentException("Length of IV cannot be more than block size! Block size: " + blockSize + ", IV length: " + iv.length);
        }

        this.iv = iv;
        this.blockSize = blockSize;
    }

    @Override
    public byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        List<Pair<Integer, Future<byte[]>>> futures = new ArrayList<>();
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        for (int i = 0; i < split.length; ++i) {
            int finalI = i;
            futures.add(Pair.of(i, service.submit(() -> Utility.xor(split[finalI], encrypter.encrypt(getCounter(iv, finalI))))));
        }
        return Utility.queryResult(futures, blockSize, src.length);
    }

    @Override
    public byte[] reverse(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        List<Pair<Integer, Future<byte[]>>> futures = new ArrayList<>();
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        for (int i = 0; i < split.length; ++i) {
            int finalI = i;
            futures.add(Pair.of(i, service.submit(() -> Utility.xor(split[finalI], encrypter.encrypt(getCounter(iv,finalI))))));
        }
        return Utility.queryResult(futures, blockSize, src.length);
    }

    private byte[] getCounter(byte[] left, int right) {
        byte[] counter = new byte[blockSize];
        int j = 0;
        for (int i = 0; i < blockSize; ++i) {
            if (i < left.length) {
                counter[i] |= left[i];
            } else {
                counter[blockSize - ++j] |= (byte) right;
                right >>>= 8;
            }
        }
        return counter;
    }

}
