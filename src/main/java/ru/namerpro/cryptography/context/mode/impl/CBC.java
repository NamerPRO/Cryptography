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
public class CBC implements EncryptMode {

    private final ExecutorService service;
    private final byte[] iv;

    @Override
    public byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        byte[] c = new byte[src.length];
        byte[] prev_c = iv;
        for (int i = 0; i < split.length; ++i) {
            prev_c = encrypter.encrypt(Utility.xor(split[i], prev_c));
            for (int j = 0; j < blockSize; ++j) {
                c[blockSize * i + j] = prev_c[j];
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
            futures.add(Pair.of(i, service.submit(() -> Utility.xor(finalI == 0 ? iv : split[finalI - 1], encrypter.decrypt(split[finalI])))));
        }
        return Utility.queryResult(futures, blockSize, src.length);
    }

}
