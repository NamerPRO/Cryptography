package ru.namerpro.cryptography.feistel;

import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.api.EncryptingConversion;
import ru.namerpro.cryptography.api.KeyExpansion;

public class FeistelNetwork {

    private final EncryptingConversion feistelFunction;
    private final int amountOfRounds;
    private final byte[][] roundKeys;

    public FeistelNetwork(EncryptingConversion feistelFunction, byte[] key, KeyExpansion expansion, int amountOfRounds) {
        this.feistelFunction = feistelFunction;
        this.roundKeys = expansion.expandKey(key);
        this.amountOfRounds = amountOfRounds;
    }

    private byte[] run(byte[] block, boolean isEncrypt) {
        byte[][] split = Utility.splitToBlocks(block, block.length / 2);
        byte[] left = split[0];
        byte[] right = split[1];
        for (int i = 0; i < amountOfRounds - 1; ++i) {
            byte[] newRightBlock = feistelFunction.runFeistelFunction(right, roundKeys[isEncrypt ? i : amountOfRounds - i - 1]);
            newRightBlock = Utility.xor(newRightBlock, left);
            left = right;
            right = newRightBlock;
        }
        return Utility.glue(Utility.xor(feistelFunction.runFeistelFunction(right, roundKeys[isEncrypt ? amountOfRounds - 1 : 0]), left), right);
    }

    public byte[] encrypt(byte[] block) {
        return run(block, true);
    }

    public byte[] decrypt(byte[] block) {
        return run(block, false);
    }

}
