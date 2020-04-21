import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Jan Kubeša
 */
public class SpakeAlice {
    private X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
    private ECDomainParameters ecparams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
    private final SecureRandom random = new SecureRandom();
    private final ECKeyPairGenerator gen = new ECKeyPairGenerator();
    private AsymmetricCipherKeyPair alicePair = null;
    private ECPublicKeyParameters alicepublic = null;
    private ECPrivateKeyParameters aliceprivate = null;
    private ECPoint bigY = null;
    private  BigInteger smally;
    private BigInteger PIN = BigInteger.valueOf(1234);
    ECPoint bigN = ecparams.getCurve().decodePoint(Hex.decode("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));
    ECPoint bigM = ecparams.getCurve().decodePoint(Hex.decode("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
    public ECPoint bigS = null;

    public SpakeAlice() {
        gen.init(new ECKeyGenerationParameters(ecparams, random));
        alicePair = gen.generateKeyPair();
        alicepublic = (ECPublicKeyParameters) alicePair.getPublic();
        aliceprivate = (ECPrivateKeyParameters) alicePair.getPrivate();
        ECPoint bigY = alicepublic.getQ();
        smally = aliceprivate.getD();
        bigS = bigN.multiply(PIN).add(bigY);
    }

    public ECPoint calculateShared(ECPoint bigT) {
        ECPoint shared2 = bigT.subtract(bigM.multiply(PIN)).multiply(smally);
        return shared2;
    }
}
