package ru.namerpro.cryptography.symmetricencrypters.deal;

import lombok.RequiredArgsConstructor;
import ru.namerpro.cryptography.api.EncryptingConversion;
import ru.namerpro.cryptography.symmetricencrypters.des.DES;

@RequiredArgsConstructor
public class DealFeistelFunction implements EncryptingConversion {

    private final DES des;

    @Override
    public byte[] runFeistelFunction(byte[] block, byte[] roundKey) {
        return des.encrypt(block);
    }

}
