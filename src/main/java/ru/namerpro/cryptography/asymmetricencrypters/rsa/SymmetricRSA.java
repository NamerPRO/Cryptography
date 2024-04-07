package ru.namerpro.cryptography.asymmetricencrypters.rsa;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import ru.namerpro.cryptography.api.symmetric.SymmetricEncrypter;

@RequiredArgsConstructor
public class SymmetricRSA implements SymmetricEncrypter {

    private final RSA rsa;
    private final RSA.RSAKeyGenerator.PublicKey publicKey;
    private final RSA.RSAKeyGenerator.PrivateKey privateKey;

    @SneakyThrows
    @Override
    public byte[] encrypt(byte[] block) {
        return rsa.encrypt(block, publicKey).get()[0];
    }

    @SneakyThrows
    @Override
    public byte[] decrypt(byte[] block) {
        byte[][] rsaBlock = new byte[1][];
        rsaBlock[0] = block;
        return rsa.decrypt(rsaBlock, privateKey).get();
    }

}
