package com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;
import java.util.Random;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;

public class AES_CBCEncryptor extends Encryptor{
    
    public AES_CBCEncryptor(ProgressIndicator progressIndicator) {
        super(progressIndicator);
    }

    @Override
    public Task encrypt(File in, File out, byte[] key) {
        return new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                Random random=new Random();
                byte[] IV=new byte[AES.BLOCK_SIZE];
                random.nextBytes(IV);
                
                
                
                
                return null;
            }
        };
    }

    @Override
    public Task decrypt(File in, File out, byte[] key) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    
}
