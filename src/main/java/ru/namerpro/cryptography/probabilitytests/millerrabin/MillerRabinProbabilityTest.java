package ru.namerpro.cryptography.probabilitytests.millerrabin;

import ru.namerpro.cryptography.probabilitytests.BaseProbabilityTest;
import ru.namerpro.cryptography.utils.stateless.CryptoMath;

import java.math.BigInteger;

public class MillerRabinProbabilityTest extends BaseProbabilityTest {

    @Override
    protected int getRoundAmount(float probability) {
        return (int) Math.ceil(-Math.log10(1 - probability) / Math.log10(4));
    }

    @Override
    protected boolean test(BigInteger candidate, BigInteger value) {
        BigInteger valueMinusOne = value.subtract(BigInteger.ONE);
        BigInteger maxPowOfTwo = valueMinusOne.and(valueMinusOne.subtract(BigInteger.ONE).not());
        BigInteger d = valueMinusOne.divide(maxPowOfTwo);
        if (CryptoMath.pow(candidate, d, value).equals(BigInteger.ONE)) {
            return true;
        }
        BigInteger number;
        int r = 0;
        do {
            number = BigInteger.ONE.shiftLeft(r);
            if (CryptoMath.pow(candidate, number.multiply(d), value).equals(valueMinusOne)) {
                return true;
            }
            ++r;
        } while (number.compareTo(maxPowOfTwo) < 0);
        return false;
    }

}
