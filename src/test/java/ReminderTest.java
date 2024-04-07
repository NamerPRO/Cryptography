import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import ru.namerpro.cryptography.utils.stateless.CryptoGF;

class ReminderTest {

    @ParameterizedTest(name = "Testing CryptoGF.reminder8 ({0} mod {1} -> {2})")
    @CsvSource({
            "0x344, 0x01, 0x47",
            "0x804, 0x1B, 0xDC",
            "0x428B, 0x1B, 0x27",
            "0x00, 0x12, 0x00"
    })
    void reminder8StandardTest(int x, int mod, int expected) {
        Assertions.assertEquals((byte) expected, CryptoGF.reminder8((char) x, (byte) mod));
    }

    @ParameterizedTest(name = "Testing CryptoGF.reminder8 ({0} mod {1} -> ArithmeticException)")
    @CsvSource({
            "0x00, 0x00",
            "0x01, 0x00"
    })
    void reminder8ExceptionTest(int x, int mod) {
        Assertions.assertThrows(ArithmeticException.class, () -> CryptoGF.reminder8((char) x, (byte) mod));
    }

    @ParameterizedTest(name = "Testing CryptoGF.reminder ({0} mod {1} -> {2})")
    @CsvSource({
            "0xAD, 0x1B, 0x02",
            "0x180, 0x01, 0x00"
    })
    void reminderStandardTest(int x, int mod, int expected) {
        Assertions.assertEquals((byte) expected, CryptoGF.reminder((char) x, (byte) mod));
    }

    @ParameterizedTest(name = "Testing CryptoGF.reminder ({0} mod {1} -> {2})")
    @CsvSource({
            "0xAD, 0x00, 0x02"
    })
    void reminderExceptionTest(int x, int mod, int expected) {
        Assertions.assertThrows(ArithmeticException.class, () -> CryptoGF.reminder((char) x, (byte) mod));
    }

}
