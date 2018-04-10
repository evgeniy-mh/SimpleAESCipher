package com.evgeniy_mh.simpleaescipher.AESEngine.CCM;

import com.evgeniy_mh.simpleaescipher.AESEngine.AES_CTREncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.ECBCEncryptor;
import com.evgeniy_mh.simpleaescipher.AESEngine.HMACEncryptor;
import com.evgeniy_mh.simpleaescipher.CommonUtils;
import com.evgeniy_mh.simpleaescipher.FileUtils;
import com.evgeniy_mh.simpleaescipher.MACOptions;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;

public class Encrypt_then_MAC {

    private AES_CTREncryptor mAESEncryptor;

    public Encrypt_then_MAC(ProgressIndicator progressIndicator) {
        mAESEncryptor = new AES_CTREncryptor(progressIndicator);
    }

    public Task encrypt(File in, File out, MACOptions options) {
        return new Task<Void>() {
            @Override
            protected Void call() throws IOException {
                mAESEncryptor.encrypt(in, out, options.getKey1()).run();
                Task MACTask = null;
                switch (options.getType()) {
                    case ECBC:
                        ECBCEncryptor ecbce = new ECBCEncryptor();
                        MACTask = ecbce.getECBC(out, null, options.getKey1(), options.getKey2(), true);
                        break;
                    case HMAC:
                        HMACEncryptor hmace = new HMACEncryptor();
                        MACTask = hmace.getHMAC(out, null, options.getKey1(), true);
                        break;
                }
                Thread MACThread = new Thread(MACTask);
                MACThread.start();

                try {
                    MACThread.join();
                } catch (InterruptedException ex) {
                    CommonUtils.reportExceptionToMainThread(ex, "MACThread.join();");
                }
                return null;
            }
        };
    }

    /**
     * Выполняет дешифрование файла
     *
     * @param in Файл шифрованного текста
     * @param out Файл для сохранения результата расшифрования (будет
     * перезаписан)
     */
    public Task decrypt(File in, File out, MACOptions options) {
        return new Task<Boolean>() {
            @Override
            protected Boolean call() throws IOException {

                byte[] MACFromFile = FileUtils.readBytesFromFile(in, (int) in.length() - 16, (int) in.length());
                File tempFile = new File(in.toPath() + "_temp");
                FileUtils.createFileCopy(in, tempFile, in.length() - 16);
                
                byte[] MAC = null;
                switch (options.getType()) {
                    case ECBC:
                        ECBCEncryptor ecbce = new ECBCEncryptor();
                        MAC = ecbce.getECBC(tempFile, options.getKey1(), options.getKey2());
                        break;
                    case HMAC:
                        HMACEncryptor hmace = new HMACEncryptor();
                        MAC = hmace.getHMAC(FileUtils.readBytesFromFile(tempFile, (int) tempFile.length()), options.getKey1());
                        break;                        
                }               
                
                if (MAC != null && Arrays.equals(MACFromFile, MAC)) {
                    mAESEncryptor.decrypt(tempFile, out, options.getKey1()).run();  
                    tempFile.delete();
                    return true;
                } else {
                    tempFile.delete();
                    return false;
                }
            }
        };
    }
}
