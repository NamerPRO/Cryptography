import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import ru.namerpro.cryptography.permutaion.Permutation;

public class PermutationFromRightFirstIsOneTests {

    @Test
    public void permutationFromRightFirstIsOneTestOne() {
        byte[] input = Permutation.toByteArray(181);
        int[] pBlock = { 1, 2, 4, 7, 3, 8, 6, 5 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(143), output);
    }

    @Test
    public void permutationFromRightFirstIsOneTestTwo() {
        byte[] input = Permutation.toByteArray(2040480607);
        int[] pBlock = { 1, 6, 7, 8 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(10), output);
    }

    @Test
    public void permutationFromRightFirstIsOneTestThree() {
        byte[] input = Permutation.toByteArray(2040480607);
        int[] pBlock = { 9, 1, 17, 24, 25, 31 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(63), output);
    }

    @Test
    public void permutationFromRightFirstIsOneTestFour() {
        byte[] input = Permutation.toByteArray(1000);
        int[] pBlock = { 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(1000), output);
    }

    @Test
    public void permutationFromRightFirstIsOneTestFive() {
        byte[] input = Permutation.toByteArray(0);
        int[] pBlock = { 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ONE));
    }

    @Test
    public void permutationFromRightFirstIsOneTestSix() {
        byte[] input = Permutation.toByteArray(0);
        int[] pBlock = { 0 };

        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ONE));
    }

    @Test
    public void permutationFromRightFirstIsOneTestSeven() {
        byte[] input = Permutation.toByteArray(0);
        int[] pBlock = { -1 };

        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ONE));
    }

    @Test
    public void permutationFromRightFirstIsOneTestEight() {
        byte[] input = Permutation.toByteArray(0);
        int[] pBlock = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        byte[] expected = { 0, 0 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_RIGHT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(expected, output);
    }

}
