package cn.edu.buaa.crypto.encryption.fspibme;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.generators.FSPIBMEDecrtptionGenerator;
import cn.edu.buaa.crypto.encryption.fspibme.generators.FSPIBMEEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.fspibme.generators.FSPIBMEKeyGenerator;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

public class FSPIBMEEngine {
    //Scheme name, used for exceptions
    public static final String SCHEME_NAME = "FS-PIBME";

    private static FSPIBMEEngine engine;
    String default_path = "benchmarks/encryption/fs-PIBME/";
    Out out = new Out(default_path + "fs-pibme");
    long startTime, endTime;

    public static FSPIBMEEngine getInstance() {
        if (engine == null) {
            engine = new FSPIBMEEngine();
        }
        return engine;
    }


    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxDepth) {
        HIBEBBG05KeyPairGenerator keyPairGenerator = new HIBEBBG05KeyPairGenerator();
        keyPairGenerator.init(new HIBEKeyPairGenerationParameter(pairingParameters, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }


    public FSPIBMEKeySerParameter RkeyGen(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String... ids) {

        FSPIBMEKeyGenerator SecretKeyGenerator = new FSPIBMEKeyGenerator();
        SecretKeyGenerator.init(publicKey, masterKey, hibebbg05Engine, ids);

        return SecretKeyGenerator.generateKey();
    }


    public FSPIBMECiphertextSerParameter encryption(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, Element message, String... tau) {

        FSPIBMEEncryptionGenerator encryptionGenerator = new FSPIBMEEncryptionGenerator();
        encryptionGenerator.init(hibebbg05Engine, publicKey, message, tau);

        return encryptionGenerator.computeEncapsulation();
    }


    public Element decryption(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, FSPIBMEKeySerParameter dk,
                              FSPIBMECiphertextSerParameter ciphertext, String... tau) throws InvalidCipherTextException {
        FSPIBMEDecrtptionGenerator decrtptionGenerator = new FSPIBMEDecrtptionGenerator();
        decrtptionGenerator.init(hibebbg05Engine, publicKey, dk, ciphertext, tau);
        return decrtptionGenerator.computeDecapsulation();
    }

    public FSPIBMEKeySerParameter Puncture(PairingKeySerParameter publicKey, FSPIBMEKeySerParameter rk, HIBEBBG05Engine engine, String... punId) {

        String punctureNode = null;
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < punId.length; i++) {
            sb.append(punId[i]);
        }
        punctureNode = sb.toString();

        out.println("Puncture : ");
        out.println("目前RK拥有的结点秘钥 ：" + rk.getTk().keySet());
        out.println("刺穿结点" + punctureNode + "在第" + (punctureNode.length() + 1) + "层");
        startTime = System.currentTimeMillis();

        //System.out.println("刺穿结点" + punctureNode + "在第" + (punctureNode.length() + 1) + "层");
        Map<String, PairingKeySerParameter> tkP = PairingUtils.PunctureTree(publicKey, engine, rk.getTk(), punctureNode);

        out.println("刺穿后RK拥有的结点秘钥 ：" + rk.getTk().keySet());
        endTime = System.currentTimeMillis();
        out.println("Puncture运行时间：" + (endTime - startTime) + "ms");
        out.println();

        rk.setTk(tkP);
        return rk;
    }
//
//    public FSPIBMEKeySerParameter Update(PairingKeySerParameter publicKey, FSPIBMEKeySerParameter rk, HIBEBBG05Engine engine, String tau) {
//
//        //String id[] = null;
//
//        String[] rho = rk.getRho();
//        String punctureNode = null;
//
//        for (int i = 1; i < rho.length; i++) {
//            if (punctureNode == null)
//                punctureNode = rho[i];
//            else
//                punctureNode = punctureNode + rho[i];
//        }
//
//        punctureNode = punctureNode + tau;
//        out.println("Update : ");
//        out.println("目前RK拥有的结点秘钥 ：" + rk.getTk().keySet());
//
//        out.println("刺穿结点" + punctureNode + "在第" + (punctureNode.length() + 1) + "层");
//        startTime = System.currentTimeMillis();
//        System.out.println("刺穿结点" + punctureNode + "在第" + (punctureNode.length() + 1) + "层");
//
//        Map<String, HIBEBBG05SecretKeySerParameter> tkP = PairingUtils.PunctureTree(publicKey, engine, rk.getTk(), punctureNode);
//
//        out.println("更新后RK拥有的结点秘钥 ：" + rk.getTk().keySet());
//        endTime = System.currentTimeMillis();
//        out.println("Update运行时间：" + (endTime - startTime) + "ms");
//        out.println();
//
//        rk.setTK(tkP);
//        return rk;
//    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
