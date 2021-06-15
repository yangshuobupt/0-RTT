package cn.edu.buaa.crypto.encryption.fspibme;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.utils.BinaryTreeBuild;
import cn.edu.buaa.crypto.encryption.fspibme.utils.TestUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class RTTMain {
    public static void main(String[] args) throws InvalidCipherTextException {
        long startTime, endTime;

        String[] taus = {"00000000000", "000000000000", "0000000000000", "000000000000", "000000000000", "000000000000"};
        String[] tags = {"000", "000", "000", "00", "000", "0000"};

        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        FSPIBMEEngine fspibmeEngine = FSPIBMEEngine.getInstance();
        HIBEBBG05Engine engine = HIBEBBG05Engine.getInstance();

        //Setup
        startTime = System.currentTimeMillis();
        PairingKeySerPair keyPair = engine.setup(pairingParameters, BinaryTreeBuild.depth);
        PairingKeySerParameter publicKey = keyPair.getPublic();
        PairingKeySerParameter masterKey = keyPair.getPrivate();
        endTime = System.currentTimeMillis();
        System.out.println("setup运行时间：" + (endTime - startTime) + "ms");

        for (int j = 0; j < 6; j++) {
            String[] ids = null;
            int num = 16;
            for (int i = 0; i <= num; i++) {
                if (i == 0) {
                    ids = new String[num + 1];
                    ids[0] = "E";
                } else {
                    ids[i] = "0";
                }
            }
            String tau = taus[j];
            String tag = tags[j];
            //Keygen
            startTime = System.currentTimeMillis();
            FSPIBMEKeySerParameter rk = fspibmeEngine.RkeyGen(engine, publicKey, masterKey, ids);
            //System.out.println("目前RK拥有的结点秘钥 ：" + rk.getTk().keySet());
            endTime = System.currentTimeMillis();
            System.out.println("RKGEN运行时间：" + (endTime - startTime) + "ms");

            //Encryption
            Element message = pairing.getGT().newRandomElement().getImmutable();
            startTime = System.currentTimeMillis();
            FSPIBMECiphertextSerParameter ciphertext = fspibmeEngine.encryption(engine, publicKey, message, ids);
            endTime = System.currentTimeMillis();
            System.out.println("加密运行时间：" + (endTime - startTime) + "ms");
            System.out.println("enc" + message);

            //Decryption
            startTime = System.currentTimeMillis();
            Element anMessage = fspibmeEngine.decryption(engine, publicKey, rk, ciphertext, ids);
            endTime = System.currentTimeMillis();
            System.out.println("解密运行时间：" + (endTime - startTime) + "ms");
            System.out.println("dec" + anMessage);

            //puncture
            System.out.println("======Puncture=====");
            startTime = System.currentTimeMillis();
            rk = fspibmeEngine.Puncture(publicKey, rk, engine, ids);
            endTime = System.currentTimeMillis();
            System.out.println("Puncture运行时间：" + (endTime - startTime) + "ms");
            //System.out.println("目前RK拥有的结点秘钥有" + rk.getTk().keySet().size() + "个 ：" + rk.getTk().keySet());
        }


    }
}
