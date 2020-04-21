import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Jan Kubeša
 */
public class Spake {
    public static void main(String[] args) throws IOException {
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters ecparams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
        final SecureRandom random = new SecureRandom();
        final ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ecparams, random));
        AsymmetricCipherKeyPair alicePair = gen.generateKeyPair();
        AsymmetricCipherKeyPair bobPair = gen.generateKeyPair();
        ECPublicKeyParameters bobpublic = (ECPublicKeyParameters) bobPair.getPublic();
        ECPublicKeyParameters alicepublic = (ECPublicKeyParameters) alicePair.getPublic();
        ECPrivateKeyParameters bobprivate = (ECPrivateKeyParameters) bobPair.getPrivate();
        ECPrivateKeyParameters aliceprivate = (ECPrivateKeyParameters) alicePair.getPrivate();
        ECPoint bigX = bobpublic.getQ();
        BigInteger smallx = bobprivate.getD();
        ECPoint bigY = alicepublic.getQ();
        BigInteger smally = aliceprivate.getD();
        BigInteger PIN = BigInteger.valueOf(1234);
        ECPoint bigN = ecparams.getCurve().decodePoint(Hex.decode("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));
        ECPoint bigM = ecparams.getCurve().decodePoint(Hex.decode("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
        ECPoint bigT = bigM.multiply(PIN).add(bigX);
        ECPoint bigS = bigN.multiply(PIN).add(bigY);
        ECPoint shared1 = bigS.subtract(bigN.multiply(PIN)).multiply(smallx);
        ECPoint shared2 = bigT.subtract(bigM.multiply(PIN)).multiply(smally);
        System.out.println(shared1.equals(shared2));
        byte[] tosend = shared1.getEncoded(true);
        System.out.println(tosend.length);
        ECPoint decoded = ecparams.getCurve().decodePoint(tosend);
        System.out.println(decoded.equals(shared2));


    }


}
