/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simpleapdu;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import opencrypto.jcmathlib.*;

/**
 *
 * @author kubes
 */
public class MathTest extends javacard.framework.Applet {
    private byte dataArray[] = null;
    ECConfig        ecc = null;
    ECCurve         curve = null;
    ECPoint         bigX = null;
    ECPoint         bigT = null;
    KeyPair         kp = null;
    ECPrivateKey    privkey = null;
    ECPublicKey     pubkey = null;
    Bignat          smallx = null;
    Bignat          userpin = null;
    
    final static byte[] PIN_TEST = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};
    final static byte[] N_COMPRESSED = {(byte) 0x03, (byte) 0xD8, (byte) 0xBB, (byte) 0xD6, (byte) 0xC6, (byte) 0x39, (byte) 0xC6, (byte) 0x29, (byte) 0x37, (byte) 0xB0, (byte) 0x4D, (byte) 0x99, (byte) 0x7F, (byte) 0x38, (byte) 0xC3, (byte) 0x77, (byte) 0x07, (byte) 0x19, (byte) 0xC6, (byte) 0x29, (byte) 0xD7, (byte) 0x01, (byte) 0x4D, (byte) 0x49, (byte) 0xA2, (byte) 0x4B, (byte) 0x4F, (byte) 0x98, (byte) 0xBA, (byte) 0xA1, (byte) 0x29, (byte) 0x2B, (byte) 0x49};
    final static byte[] M_COMPRESSED = {(byte) 0x02, (byte) 0x88, (byte) 0x6E, (byte) 0x2F, (byte) 0x97, (byte) 0xAC, (byte) 0xE4, (byte) 0x6E, (byte) 0x55, (byte) 0xBA, (byte) 0x9D, (byte) 0xD7, (byte) 0x24, (byte) 0x25, (byte) 0x79, (byte) 0xF2, (byte) 0x99, (byte) 0x3B, (byte) 0x64, (byte) 0xE1, (byte) 0x6E, (byte) 0xF3, (byte) 0xDC, (byte) 0xAB, (byte) 0x95, (byte) 0xAF, (byte) 0xD4, (byte) 0x97, (byte) 0x33, (byte) 0x3D, (byte) 0x8F, (byte) 0xA1, (byte) 0x2F};

    public MathTest(byte[] buffer, short offset, byte length) {
        dataArray = new byte[100];
        Util.arrayFillNonAtomic(dataArray, (short) 0, (short) 100, (byte) 0);
        // Pre-allocate all helper structures
        ecc = new ECConfig((short) 256); 
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        bigX = new ECPoint(curve, ecc.ech);
        bigT = new ECPoint(curve, ecc.ech);
        kp = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
        kp.genKeyPair();
        privkey = (ECPrivateKey) kp.getPrivate();
        pubkey = (ECPublicKey) kp.getPublic();
        short smallxlen = privkey.getS(dataArray, (short) 0);
        byte[] smallxdata = new byte[smallxlen];
        privkey.getS(smallxdata, (short) 0);
        smallx = new Bignat(smallxdata, ecc.bnh);
        userpin = new Bignat(PIN_TEST,ecc.bnh);
    }
    // Installation of our applet
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MathTest(bArray, bOffset, bLength).register();
    }
    public boolean select() {
        // Restore values which were cleared after card reset 
        ecc.refreshAfterReset(); 
        return true;
    }
    
    // NOTE: very simple EC usage example - no cla/ins, no communication with host...    
    public void process(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        byte[] testarray =new byte[200]; // doesnt bothered about the size..
        short dataLen = apdu.setIncomingAndReceive();
        if (selectingApplet()) { return; } // Someone is going to use our applet
        bigT.setW(M_COMPRESSED, (short) 0, (short) M_COMPRESSED.length); //T = M
        bigT.multiplication_x(userpin, testarray, (short)0);//userpin is Bignat Scalar, wM stored in testarray.

        //bigT.multiplication(PIN_TEST, (short) 0, (byte) PIN_TEST.length); //T = wM - this multiplication is causing the issue
        //bigT.makeDouble(); - This does not work either
        short bigXlen = pubkey.getW(dataArray, (short) 0); // getting X length and saving it to "disk" as raw bytes
        bigX.setW(dataArray, (short) 0, bigXlen); // making X point
        bigT.add(bigX); //T = wM + X
        short tlen = bigX.getW(dataArray,(short) 0);
        Util.arrayCopyNonAtomic(dataArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, tlen);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, tlen);
    }
}
