/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package usn.net.ssl.util;

import java.io.File;
import java.security.KeyStore;

/**
 *
 * @author Dad
 */
public class KeyStoreWrapper {

    private KeyStore store;
    private File keyStoreLocation;
    private char[] keyStorePassword;

    public KeyStore getStore() {
        return store;
    }

    public void clear() {

        for (int i = 0; i < keyStorePassword.length; i++) {
            keyStorePassword[i] = (char) 0;
        }
        keyStorePassword = null;
        keyStoreLocation = null;
    }

    public void setStore(KeyStore store) {
        this.store = store;
    }

    public File getKeyStoreLocation() {
        return keyStoreLocation;
    }

    public void setKeyStoreLocation(File keyStoreLocation) {
        this.keyStoreLocation = keyStoreLocation;
    }

    public char[] getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(char[] keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof KeyStoreWrapper) {
            return keyStoreLocation.equals(((KeyStoreWrapper) other).keyStoreLocation);
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + (this.keyStoreLocation != null ? this.keyStoreLocation.hashCode() : 0);
        return hash;
    }

   
    

}
