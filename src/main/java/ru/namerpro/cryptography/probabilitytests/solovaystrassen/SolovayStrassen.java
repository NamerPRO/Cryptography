package ru.namerpro.cryptography.probabilitytests.solovaystrassen;

import ru.namerpro.cryptography.probabilitytests.BaseProbabilityTest;
import ru.namerpro.cryptography.utils.stateless.CryptoMath;

import java.math.BigInteger;

public class SolovayStrassen extends BaseProbabilityTest {

    @Override
    protected int getRoundAmount(float probability) {
        return (int) Math.ceil(-Math.log10(1 - probability) / Math.log10(2));
    }

    @Override
    protected boolean test(BigInteger candidate, BigInteger value) {
        BigInteger lhs = CryptoMath.pow(candidate, value.subtract(BigInteger.ONE).divide(BigInteger.TWO), value);
        if (!lhs.equals(BigInteger.ONE) && !lhs.equals(value.subtract(BigInteger.ONE)) && !lhs.equals(BigInteger.ZERO)) {
            return false;
        }
        int rhs = CryptoMath.jacobyOf(candidate, value);
        return lhs.equals(BigInteger.valueOf(rhs).add(value).remainder(value));
    }

}
