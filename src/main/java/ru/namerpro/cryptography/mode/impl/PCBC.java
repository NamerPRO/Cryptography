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
public class PCBC implements EncryptMode {

    private final ExecutorService service;
    private final byte[] iv;

    @Override
    public byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        byte[] c = new byte[src.length];
        byte[] prevC = { 0 };
        for (int i = 0; i < split.length; ++i) {
            prevC = encrypter.encrypt(Utility.xor(split[i], (i == 0 ? iv : Utility.xor(split[i - 1], prevC))));
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
            futures.add(Pair.of(i, service.submit(() -> encrypter.decrypt(split[finalI]))));
        }
        byte[][] decryptData = (byte[][]) Utility.queryResult(futures, blockSize, -1, true);
        byte[] m = new byte[src.length];
        byte[] prevM = { 0 };
        for (int i = 0; i < decryptData.length; ++i) {
            prevM = Utility.xor(decryptData[i], (i == 0 ? iv : Utility.xor(split[i - 1], prevM)));
            for (int j = 0; j < blockSize; ++j) {
                m[blockSize * i + j] = prevM[j];
            }
        }
        return m;
    }

}
