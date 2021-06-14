package com.example.encryption.hibe;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.FSPIBMEEngine;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.utils.BinaryTreeBuild;
import cn.edu.buaa.crypto.encryption.fspibme.utils.TestUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.utils.FileTransferClient;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.junit.Test;

import java.io.*;


public class RTTJUnitTest {

    @Test
    public void test1() throws Exception {

        ObjectOutputStream oos;
        ObjectInputStream ois;
        File file;
        long startTime, endTime;

        FileTransferClient client = new FileTransferClient();

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
        //String[] ids = {"E", "0", "0", "0","0", "0", "0","0", "0", "0","0", "0", "0","0", "0","0","0"};
        String tau = "0000000000000";
        String tag = "000";

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
//
//        oos = new ObjectOutputStream(new FileOutputStream("outputs/pk"));
//        oos.writeObject(publicKey);
//        oos.close();
//        file = new File("outputs/pk");
//        ois = new ObjectInputStream(new FileInputStream(file));
//        client.sendFile("pk");
//
//        oos = new ObjectOutputStream(new FileOutputStream("outputs/msk"));
//        oos.writeObject(masterKey);
//        oos.close();
//        file = new File("outputs/msk");
//        ois = new ObjectInputStream(new FileInputStream(file));
//        client.sendFile("msk");


        //Keygen
        startTime = System.currentTimeMillis();
        FSPIBMEKeySerParameter rk = fspibmeEngine.RkeyGen(engine, publicKey, masterKey, ids);


        oos = new ObjectOutputStream(new FileOutputStream("outputs/rk"));
        oos.writeObject(rk);
        oos.close();
        file = new File("outputs/rk");
        ois = new ObjectInputStream(new FileInputStream(file));
        //FSPIBMEKeySerParameter newSk = (FSPIBMEKeySerParameter) ois.readObject();
        System.out.println(System.currentTimeMillis());
        client.sendFile("rk");


        System.out.println("目前RK拥有的结点秘钥 ：" + rk.getTk().keySet());
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
        System.out.println("目前RK拥有的结点秘钥有" + rk.getTk().keySet().size() + "个 ：" + rk.getTk().keySet());


//        Set<String> set1 = rk.getTk().keySet();
//        //Update
//        System.out.println("======Update=====");
//        startTime = System.currentTimeMillis();
//        rk = fspibmeEngine.Update(publicKey, rk, engine, updateID[j]);
//        endTime = System.currentTimeMillis();
//        System.out.println("Update运行时间：" + (endTime - startTime) + "ms");
//        System.out.println("目前RK拥有的结点秘钥有" + rk.getTk().keySet().size() + "个 ：" + rk.getTk().keySet());
//        Set<String> set2 = rk.getTk().keySet();
//        setCompare(set1, set2);

        client.close();

    }
}
