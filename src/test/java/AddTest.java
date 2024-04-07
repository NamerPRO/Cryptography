import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import ru.namerpro.cryptography.utils.stateless.CryptoGF;

class AddTest {

    @ParameterizedTest(name = "Testing CryptoGF.add ({0}, {1} -> {0} ^ {1})")
    @CsvSource({
            "100, 25, 125",
            "7, 7, 0",
            "255, 132, 123"
    })
    void testAddition(int x, int y, int expected) {
        Assertions.assertEquals((byte) expected, CryptoGF.add((byte) x, (byte) y));
    }

}
