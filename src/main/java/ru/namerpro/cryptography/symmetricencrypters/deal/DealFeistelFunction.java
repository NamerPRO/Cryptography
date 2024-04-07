package ru.namerpro.cryptography.symmetricencrypters.deal;

import lombok.RequiredArgsConstructor;
import ru.namerpro.cryptography.api.symmetric.networksfunctions.feistel.FeistelFunction;
import ru.namerpro.cryptography.symmetricencrypters.des.DES;

@RequiredArgsConstructor
public class DealFeistelFunction implements FeistelFunction {

    private final DES des;

    @Override
    public byte[] runFeistelFunction(byte[] block, byte[] roundKey) {
        return des.encrypt(block);
    }

}
