package ru.namerpro.cryptography.probabilitytests.fermat;

import ru.namerpro.cryptography.probabilitytests.BaseProbabilityTest;
import ru.namerpro.cryptography.utils.stateless.CryptoMath;

import java.math.BigInteger;

public class FermatProbabilityTest extends BaseProbabilityTest {

    @Override
    protected int getRoundAmount(float probability) {
        return (int) Math.ceil(-Math.log10(1 - probability) / Math.log10(2));
    }

    @Override
    protected boolean test(BigInteger candidate, BigInteger value) {
        return CryptoMath.pow(candidate, value.subtract(BigInteger.ONE), value).equals(BigInteger.ONE);
    }

}
