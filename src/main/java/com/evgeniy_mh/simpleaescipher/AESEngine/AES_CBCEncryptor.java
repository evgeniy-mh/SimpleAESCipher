package com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;

public class AES_CBCEncryptor extends Encryptor{
    
    public AES_CBCEncryptor(ProgressIndicator progressIndicator) {
        super(progressIndicator);
    }

    @Override
    Task encrypt(File in, File out, byte[] key) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    Task decrypt(File in, File out, byte[] key) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    
}
