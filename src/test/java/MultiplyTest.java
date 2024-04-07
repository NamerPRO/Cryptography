import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import ru.namerpro.cryptography.utils.stateless.CryptoGF;

class MultiplyTest {

    @ParameterizedTest(name = "Testing CryptoGF.multiply ({0} * {1} -> {2} (mod {3}))")
    @CsvSource({
            "0x57, 0x83, 0x1B, 0xC1",
            "0x99, 0x00, 0x22, 0x00",
            "0x00, 0x01, 0x12, 0x00",
            "0x00, 0x00, 0x01, 0x00",
            "0x12, 0x92, 0x1B, 0xDC",
            "0x92, 0x12, 0x1B, 0xDC",
            "0x12, 0x32, 0x01, 0x47",
            "0x12, 0x32, 0x02, 0x42"
    })
    void multiplicationSimpleTest(int x, int y, int mod, int expected) {
        Assertions.assertEquals((byte) expected, CryptoGF.multiply((byte) x, (byte) y, (byte) mod));
    }

    @ParameterizedTest(name = "Testing CryptoGF.multiply ({0} * {1} -> ArithmeticException (mod {2}))")
    @CsvSource({
            "0x00, 0x00, 0x00",
            "0x00, 0x00, 0x00",
            "0x12, 0x22, 0x00"
    })
    void multiplicationErrorTest(int x, int y, int mod) {
        Assertions.assertThrows(ArithmeticException.class, () -> CryptoGF.multiply((byte) x, (byte) y, (byte) mod));
    }

}
