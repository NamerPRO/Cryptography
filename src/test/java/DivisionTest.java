import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import ru.namerpro.cryptography.utils.stateless.CryptoGF;

class DivisionTest {

    @ParameterizedTest(name = "Testing CryptoGF.divide ({0} mod {1} -> {2})")
    @CsvSource({
            "0xAD, 0x1B, 0x0D",
            "0x00, 0x22, 0x00",
            "0x0F, 0x5, 0x3"
    })
    void divideStandardTest(int x, int mod, int expected) {
        Assertions.assertEquals((byte) expected, CryptoGF.divide((byte) x, (byte) mod));
    }

    @ParameterizedTest(name = "Testing CryptoGF.divide ({0} mod {1} -> ArithmeticException)")
    @CsvSource({
            "0xAD, 0x00"
    })
    void divideExceptionTest(int x, int mod) {
        Assertions.assertThrows(ArithmeticException.class, () -> CryptoGF.divide((byte) x, (byte) mod));
    }

}
