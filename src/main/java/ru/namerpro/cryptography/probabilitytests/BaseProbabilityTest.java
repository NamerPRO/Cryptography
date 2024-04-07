package ru.namerpro.cryptography.probabilitytests;

import ru.namerpro.cryptography.api.probability.ProbabilityTest;
import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.utils.stateless.CryptoMath;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

public abstract class BaseProbabilityTest implements ProbabilityTest {

    @Override
    public boolean isProbablyPrime(BigInteger value, float probability) {
        if (value.compareTo(BigInteger.TWO) < 0) {
            throw new IllegalArgumentException("Expected value > 1, but " + probability + " found!");
        }
        if (probability >= 1 || probability < 0) {
            throw new IllegalArgumentException("Probability cannot be negative or > 1, but " + probability + " found!");
        }
        if (probability < 0.5f) {
            probability = 0.5f;
        }
        int roundsAmount = getRoundAmount(probability);
        Set<BigInteger> witness = new HashSet<>();
        for (int i = 0; i < roundsAmount; ++i) {
            BigInteger candidate;
            do {
                candidate = Utility.getRandom(BigInteger.valueOf(2), value);
            } while (witness.contains(candidate));
            if (CryptoMath.gcd(value, candidate).compareTo(BigInteger.ONE) != 0) {
                return false;
            }
            if (test(candidate, value)) {
                witness.add(candidate);
            } else {
                return false;
            }
        }
        return true;
    }

    protected abstract int getRoundAmount(float probability);
    protected abstract boolean test(BigInteger candidate, BigInteger value);

}
