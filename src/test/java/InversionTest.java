import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import ru.namerpro.cryptography.utils.stateless.CryptoGF;

class InversionTest {

    @ParameterizedTest(name = "Testing CryptoGF.inverse8 ({0}^-1 -> {2} (mod {1}))")
    @CsvSource({
            "0x1, 0x27, 0x01",
            "0x84, 0x1B, 0x96",
            "0x4D, 0x1B, 0x25",
            "0x00, 0x25, 0x00"
    })
    void inversion8StandardTest(int x, int mod, int expected) {
        Assertions.assertEquals((byte) expected, CryptoGF.inverse8((byte) x, (byte) mod));
    }

    @ParameterizedTest(name = "Testing CryptoGF.inverse8 ({0}^-1 -> ArithmeticException)")
    @CsvSource({
            "0xBD, 0x00"
    })
    void inversion8ExceptionTest(int x, int mod) {
        Assertions.assertThrows(ArithmeticException.class, () -> CryptoGF.inverse8((byte) x, (byte) mod));
    }

}
