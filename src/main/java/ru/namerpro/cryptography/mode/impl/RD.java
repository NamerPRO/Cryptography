package ru.namerpro.cryptography.mode.impl;

import ru.namerpro.cryptography.utils.Pair;
import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.api.symmetric.modes.EncryptMode;
import ru.namerpro.cryptography.api.symmetric.SymmetricEncrypter;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

public class RD implements EncryptMode {

    private final ExecutorService service;
    private final BigInteger initial;
    private final BigInteger delta;

    public RD(ExecutorService service, byte[] iv) {
        this.service = service;

        int blockSize = iv.length / 2;
        byte[] deltaAsByteArray = new byte[blockSize + 1];
        byte[] initialAsByteArray = new byte[iv.length + 1];
        for (int i = 1; i <= iv.length; ++i) {
            if (i < deltaAsByteArray.length) {
                deltaAsByteArray[i] = iv[i + blockSize - 1];
            }
            initialAsByteArray[i] = iv[i - 1];
        }

        this.delta = new BigInteger(deltaAsByteArray);
        this.initial = new BigInteger(initialAsByteArray);
    }

    @Override
    public byte[] apply(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        List<Pair<Integer, Future<byte[]>>> futures = new ArrayList<>();
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        BigInteger value = initial;
        for (int i = 0; i < split.length; ++i) {
            int finalI = i;
            BigInteger finalValue = value;
            futures.add(Pair.of(i, service.submit(() -> encrypter.encrypt(Utility.xor(Utility.toByteArray(finalValue), split[finalI])))));
            value = value.add(delta);
        }
        return Utility.queryResult(futures, blockSize, src.length);
    }

    @Override
    public byte[] reverse(byte[] src, int blockSize, SymmetricEncrypter encrypter) {
        List<Pair<Integer, Future<byte[]>>> futures = new ArrayList<>();
        byte[][] split = Utility.splitToBlocks(src, blockSize);
        BigInteger value = initial;
        for (int i = 0; i < split.length; ++i) {
            int finalI = i;
            BigInteger finalValue = value;
            futures.add(Pair.of(i, service.submit(() -> Utility.xor(encrypter.decrypt(split[finalI]), Utility.toByteArray(finalValue)))));
            value = value.add(delta);
        }
        return Utility.queryResult(futures, blockSize, src.length);
    }

}
