package ru.namerpro.cryptography.mode.impl;

import lombok.RequiredArgsConstructor;
import ru.namerpro.cryptography.utils.Pair;
import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.api.EncryptMode;
import ru.namerpro.cryptography.api.SymmetricEncrypter;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

@RequiredArgsConstructor
public class CFB implements EncryptMode {

    private final ExecutorService service;
    private final byte[] iv;

    @Override
    public byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        byte[] c = new byte[src.length];
        byte[] prevC = iv;
        for (int i = 0; i < split.length; ++i) {
            prevC = Utility.xor(encrypter.encrypt(prevC), split[i]);
            for (int j = 0; j < blockSize; ++j) {
                c[blockSize * i + j] = prevC[j];
            }
        }
        return c;
    }

    @Override
    public byte[] reverse(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        List<Pair<Integer, Future<byte[]>>> futures = new ArrayList<>();
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        for (int i = 0; i < split.length; ++i) {
            int finalI = i;
            futures.add(Pair.of(i, service.submit(() -> Utility.xor(encrypter.encrypt(finalI == 0 ? iv : split[finalI - 1]), split[finalI]))));
        }
        return Utility.queryResult(futures, blockSize, src.length);
    }

}
