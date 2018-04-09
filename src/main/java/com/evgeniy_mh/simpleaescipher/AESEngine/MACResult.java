package com.evgeniy_mh.simpleaescipher.AESEngine;

public class MACResult {
    private byte[] MAC;
    
    public MACResult(byte[] MAC){
        this.MAC=MAC;
    }

    public byte[] getMAC() {
        return MAC;
    }
}
