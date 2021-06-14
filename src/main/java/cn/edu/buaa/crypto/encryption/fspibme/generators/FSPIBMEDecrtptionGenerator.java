package cn.edu.buaa.crypto.encryption.fspibme.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMECiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class FSPIBMEDecrtptionGenerator {
    private Element message;
    private HIBEBBG05PublicKeySerParameter publicKeyParameter;
    private FSPIBMECiphertextSerParameter ciphertext;
    private FSPIBMEKeySerParameter dk;
    private HIBEBBG05Engine hibebbg05Engine;
    private PairingCipherSerParameter W;
    private String[] tau;

    public void init(HIBEBBG05Engine hibebbg05Engine, PairingKeySerParameter publicKey, FSPIBMEKeySerParameter dk,
                     FSPIBMECiphertextSerParameter FSPIBMEciphertext, String... tau) {
        this.hibebbg05Engine = hibebbg05Engine;
        this.publicKeyParameter = (HIBEBBG05PublicKeySerParameter) publicKey;
        this.dk = dk;
        this.W = FSPIBMEciphertext.getW();
        this.tau = tau;
        this.ciphertext = FSPIBMEciphertext;

    }

    public Element computeDecapsulation() throws InvalidCipherTextException {

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());

        HIBEBBG05SecretKeySerParameter secretKeyParameters = (HIBEBBG05SecretKeySerParameter) dk.getTk().get("E000");

        Element sig = ciphertext.getSig();
        Element x = pairing.getZr().newElement();
        x.set(10086);

        System.out.println(PairingUtils.SigVerify(publicKeyParameter, ciphertext.getSig_pk(), sig, x));
        this.message = hibebbg05Engine.decryption(publicKeyParameter, secretKeyParameters, tau, W);
        return this.message;
    }
}
