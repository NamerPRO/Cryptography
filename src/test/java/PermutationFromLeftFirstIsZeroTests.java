import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import ru.namerpro.cryptography.permutaion.Permutation;

public class PermutationFromLeftFirstIsZeroTests {

    @Test
    public void permutationFromLeftFirstIsZeroTestOne() {
        byte[] input = Permutation.toByteArray(181);
        int[] pBlock = { 1, 2, 4, 8, 3, 7, 6, 5 };

        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ZERO));
    }

    @Test
    public void permutationFromLeftFirstIsZeroTestTwo() {
        byte[] input = Permutation.toByteArray(181);
        int[] pBlock = { 1, 2, 4, 7, 3, 0, 6, 5 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ZERO);
        Assertions.assertArrayEquals(Permutation.toByteArray(93), output);
    }

    @Test
    public void permutationFromLeftFirstIsZeroTestThree() {
        byte[] input = Permutation.toByteArray(38194214);
        int[] pBlock = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ZERO);
        Assertions.assertArrayEquals(Permutation.toByteArray(38194214), output);
    }

    @Test
    public void permutationFromLeftFirstIsZeroTestFour() {
        byte[] input = Permutation.toByteArray(38194214);
        int[] pBlock = { 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ZERO);
        Assertions.assertArrayEquals(Permutation.toByteArray(26267017), output);
    }

}
