import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.Scanner;

public class Crypto {
    public static BigInteger fastMod(BigInteger g, BigInteger a, BigInteger p) {
        int bitWidth = a.bitLength();
        BigInteger one = new BigInteger("1");
        BigInteger b = BigInteger.ZERO.add(a);
        boolean bits[] = new boolean[bitWidth];
        for (int i = 0; i < bitWidth; i++) {
            boolean bit = b.and(one).equals(one);
            bits[bitWidth-i-1] = bit;
            b.shiftRight(1);
        }

        BigInteger result = new BigInteger("1");
        for (int i = 0; i < bitWidth; i++) {
            result = result.pow(2);
            result = result.mod(p);
            if (bits[i]) {
                result = result.multiply(g);
                result = result.mod(p);
            }
        }
        return result;
    }

    public static boolean isValidG(BigInteger g, BigInteger p) {
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        if (g.modPow(BigInteger.TWO, p).equals(BigInteger.ONE)) {
            return false;
        }
        if (g.modPow(q, p).equals(BigInteger.ONE)) {
            return false;
        }
        return true;
    }

    public static BigInteger getGenerator(int bits, BigInteger p) {
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        int maxBits = Math.min(bits, p.bitLength());
        while (true) {
            BigInteger g = getRandom(maxBits - 1, maxBits);
            if (g.compareTo(BigInteger.TWO) < 0 || g.compareTo(pMinusOne) >= 0) {
                continue;
            }
            if (isValidG(g, p)) {
                return g;
            }
        }
    }

    public static BigInteger getRandom(int minBits, int maxBits) {
        BigInteger result = new BigInteger(maxBits, Rand.getRand());
        while (result.bitLength() <= minBits) {
            result = new BigInteger(maxBits, Rand.getRand());
        }
        return result;
    }

    public static boolean checkPrime(BigInteger p, int numChecks) {
        boolean isPrime = true;
        try {
            Scanner scan = new Scanner(new File("primes.txt"));
            while (scan.hasNext()) {
                BigInteger b = new BigInteger(scan.nextLine());
                if (p.mod(b).equals(BigInteger.ZERO)) {
                    isPrime = false;
                    break;
                }
            }
            scan.close();
        } catch (FileNotFoundException fnfEx) {
            fnfEx.printStackTrace();
        }
        if (!isPrime) {
            return false;
        }

        BigInteger pm = p.subtract(BigInteger.ONE);
        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            if (!fastMod(a, pm, p).equals(BigInteger.ONE)) {
                return false;
            }
        }

        BigInteger s = BigInteger.ZERO;
        BigInteger d = pm;
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            s = s.add(BigInteger.ONE);
            d = d.shiftRight(1);
        }
        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            BigInteger x = fastMod(a, d, p);
            for (BigInteger j = BigInteger.ZERO; !j.equals(s); j = j.add(BigInteger.ONE)) {
                x = x.pow(2);
                BigInteger y = x.mod(p);
                if (y.equals(BigInteger.ONE) && !x.equals(BigInteger.ONE) && !x.equals(pm)) {
                    return false;
                }
                x = y;
            }
            if (!x.equals(BigInteger.ONE)) {
                return false;
            }
        }

        return isPrime;
    }

    public static BigInteger getPrime(int minBits, int maxBits, int numChecks) {
        int i = 0;
        BigInteger p = getRandom(minBits, maxBits);
        while (!checkPrime(p, numChecks)) {
            i += 1;
            p = getRandom(minBits, maxBits);
        }
        System.out.printf("Checked %d numbers for primality%n", i);
        return p;
    }

    public static BigInteger getSafePrime() {
        while (true) {
            BigInteger q = getPrime(2048, 3072, 10);
            BigInteger p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
            if (checkPrime(p, 10)) {
                return p;
            }
        }
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return a;
        }
        return gcd(b, a.mod(b));
    }

    public static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }
        BigInteger[] values = extendedGCD(b, a.mod(b));
        BigInteger gcd = values[0];
        BigInteger x1 = values[1];
        BigInteger y1 = values[2];
        BigInteger y = x1.subtract(a.divide(b).multiply(y1));
        System.out.printf("gcd = %s, a = %s, b = %s%n", gcd, y1, y);
        return new BigInteger[]{gcd, y1, y};
    }

    public static BigInteger modularInverse(BigInteger e, BigInteger phi) {
        BigInteger[] result = extendedGCD(e, phi);
        BigInteger gcd = result[0];
        BigInteger x = result[1];
        if (!gcd.equals(BigInteger.ONE)) {
            throw new ArithmeticException("Inverse does not exist");
        }
        return x.mod(phi);
    }

    public static void main(String[] args) {
        extendedGCD(new BigInteger("65537"), new BigInteger("3120"));
    }
}