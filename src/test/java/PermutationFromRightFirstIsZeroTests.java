import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import ru.namerpro.cryptography.permutaion.Permutation;

public class PermutationFromRightFirstIsZeroTests {

    @Test
    public void permutationFromRightFirstIsZeroTestOne() {
        byte[] input = Permutation.toByteArray(0);
        int[] pBlock = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] expected = { 0, 0 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ZERO);
        Assertions.assertArrayEquals(expected, output);
    }

}
