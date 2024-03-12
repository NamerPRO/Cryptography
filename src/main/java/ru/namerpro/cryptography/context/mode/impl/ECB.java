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

@RequiredArgsConstructor
public class ECB implements EncryptMode {

    private final ExecutorService service;

    @Override
    public byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        List<Pair<Integer, Future<byte[]>>> futures = new ArrayList<>();
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        for (int i = 0; i < split.length; ++i) {
            int finalI = i;
            futures.add(Pair.of(i, service.submit(() -> encrypter.encrypt(split[finalI]))));
        }
        return Utility.queryResult(futures, blockSize, src.length);
    }

    @Override
    public byte[] reverse(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        List<Pair<Integer, Future<byte[]>>> futures = new ArrayList<>();
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        for (int i = 0; i < split.length; ++i) {
            int finalI = i;
            futures.add(Pair.of(i, service.submit(() -> encrypter.decrypt(split[finalI]))));
        }
        return Utility.queryResult(futures, blockSize, src.length);
    }

}
