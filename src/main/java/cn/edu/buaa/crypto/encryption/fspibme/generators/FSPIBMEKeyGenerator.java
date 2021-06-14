package cn.edu.buaa.crypto.encryption.fspibme.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.fspibme.serparams.FSPIBMEKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.generators.HIBEBBG05SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEDelegateGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBESecretKeyGenerationParameter;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class FSPIBMEKeyGenerator {

    private HIBEBBG05MasterSecretKeySerParameter masterSecretKeyParameter;
    private HIBEBBG05PublicKeySerParameter publicKeyParameter;
    private String[] ids;
    private HIBEBBG05Engine hibebbg05Engine;

    public void init(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, HIBEBBG05Engine hibebbg05Engine, String[] ids) {
        this.masterSecretKeyParameter = (HIBEBBG05MasterSecretKeySerParameter) masterKey;
        this.publicKeyParameter = (HIBEBBG05PublicKeySerParameter) publicKey;
        this.hibebbg05Engine = hibebbg05Engine;
        this.ids = ids;
    }

    public FSPIBMEKeySerParameter generateKey() {

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Map<String, PairingKeySerParameter> tk = new HashMap<String, PairingKeySerParameter>();
        HIBEBBG05SecretKeyGenerator secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();

        for (int i = 0; i < ids.length; i++) {
            if (i == 0) {
                String[] tempId = {ids[i]};
                secretKeyGenerator.init(new HIBESecretKeyGenerationParameter(publicKeyParameter, masterSecretKeyParameter, tempId));
                PairingKeySerParameter sk_i = secretKeyGenerator.generateKey();
                tk.put(ids[0], sk_i);
            } else {
                StringBuffer sb = new StringBuffer();
                String fatherId = null;
                for (int j = 0; j <= i; j++) {
                    sb.append(ids[j]);
                    if (j == i - 1)
                        fatherId = sb.toString();
                }
                String id = sb.toString();

                secretKeyGenerator = new HIBEBBG05SecretKeyGenerator();
                secretKeyGenerator.init(new HIBEDelegateGenerationParameter(publicKeyParameter, tk.get(fatherId), ids[i]));
                PairingKeySerParameter sk_i = secretKeyGenerator.generateKey();
                tk.put(id, sk_i);
            }
        }


        return new FSPIBMEKeySerParameter(publicKeyParameter.getParameters(), ids, tk);

    }
}
