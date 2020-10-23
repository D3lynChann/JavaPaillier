package paillier;

import java.math.*;
import java.util.*;

public class Paillier {
    // p和q是两个随机的项，lambda是p-1和q-1的最小公倍数
    private BigInteger p, q, lambda;

    // n = p * q;
    private BigInteger n;

    // n2即n的平方
    private BigInteger n2;

    /*
    随机选取一整数g，g属于小于n2的整数集，且g满足：g的lambda次方对n2求模减1
    后再除以n，最后将其与n求最大公约数为1
    gcd(((g^lambda mod n2) - 1) / n, n) = 1
     */
    private BigInteger g;

    // 模量
    private int bitLength;

    // 构造函数
    // 其中certainty表示生成素数的概率，构造函数的执行时间与此参数成正比
    public Paillier(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    // 默认构造函数
    public Paillier() {
        KeyGeneration(16, 64);
    }

    // 生成公钥n和g 私钥lambda
    public void KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        // 生成两个长度为bitLength/2的正的大素数
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());

        // 得到n和n2
        n = p.multiply(q);
        n2 = n.multiply(n);
        // 随机生成0~100的整数g
        g = new BigInteger(String.valueOf((int)(Math.random() * 100)));

        // 生成p-1和q-1的最小公倍数lambda
        // lambda = (p - 1) * (q - 1) / gcd(p - 1, q - 1)
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));

        // 检查g是否满足条件
        if (g.modPow(lambda, n2).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
            System.out.println("g is not good..., try again.");
            System.exit(1);
        }
    }

    // 加密，版本1
    public BigInteger Encryption(BigInteger m, BigInteger r) {
        // c = (g ^ m) * (r ^ n) mod n2
        return g.modPow(m, n2).multiply(r.modPow(n, n2)).mod(n2);
    }

    // 加密，版本2
    public BigInteger Encryption(BigInteger m) {
        // 随机构造r
        BigInteger r = new BigInteger(bitLength, new Random());
        return Encryption(m, r);
    }

    // 解密
    public BigInteger Decryption(BigInteger c) {
        // m = (L(c^lambda mod n2)) / (L(g ^ lambda mod n2)) mod n
        BigInteger u1 = c.modPow(lambda, n2);
        BigInteger u2 = g.modPow(lambda, n2);
        return (u1.subtract(BigInteger.ONE).divide(n)).multiply(u2.subtract(BigInteger.ONE).divide(n).modInverse(n)).mod(n);
    }

    // 密文加法
    public BigInteger add(BigInteger em1, BigInteger em2) {
        return em1.multiply(em2).mod(n2);
    }

    // 密文明文乘法
    public BigInteger mul(BigInteger em, BigInteger cl) {
        return em.modPow(cl, n2);
    }

    // 显示参数
    public void showPaillier() {
        System.out.println("p: " + p);
        System.out.println("q: " + q);
        System.out.println("n: " + n);
        System.out.println("square of n: " + n2);
        System.out.println("g: " + g);
        System.out.println("lambda: " + lambda);
    }

    public static void main(String[] args) {
        Paillier paillier = new Paillier();
        paillier.showPaillier();
        BigInteger p1 = new BigInteger("22");
        BigInteger p2 = new BigInteger("4");

        // 加密
        BigInteger c1 = paillier.Encryption(p1);
        BigInteger c2 = paillier.Encryption(p2);

        // 加密结果
        System.out.println("p1加密结果：" + c1);
        System.out.println("p2加密结果：" + c2);
        System.out.println("c1解密结果: " + paillier.Decryption(c1));
        System.out.println("c2解密结果: " + paillier.Decryption(c2));

        // 测试加法
        BigInteger resSum = paillier.add(c1, c2);
        System.out.println("加法结果（加密）: " + resSum);
        System.out.println("加法结果: " + paillier.Decryption(resSum));

        // 测试乘法
        BigInteger productSum = paillier.mul(c1, p2);
        System.out.println("乘法结果（加密）: " + productSum);
        System.out.println("乘法结果: " + paillier.Decryption(productSum));
    }
}
