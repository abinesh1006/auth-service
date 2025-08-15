package com.auth.service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class KeyManagementService {
    
    private static final Logger logger = LoggerFactory.getLogger(KeyManagementService.class);
    
    @Value("${auth.server.jwk.private-key:}")
    private String privateKeyValue;
    
    @Value("${auth.server.jwk.public-key:}")
    private String publicKeyValue;
    
    @Value("${auth.server.jwk.key-size}")
    private int keySize;
    
    public KeyPair getOrCreateKeyPair() {
        try {
            // Try to load keys from properties first
            if (StringUtils.hasText(privateKeyValue) && StringUtils.hasText(publicKeyValue)) {
                logger.info("Loading RSA key pair from application properties");
                return loadKeyPairFromProperties();
            } else {
                logger.warn("No RSA keys found in properties. Generating new key pair (will change on restart!)");
                return generateKeyPair();
            }
        } catch (Exception e) {
            logger.error("Error loading key pair from properties, falling back to in-memory generation", e);
            return generateKeyPair();
        }
    }
    
    private KeyPair loadKeyPairFromProperties() throws Exception {
        // Clean and decode private key
        String cleanedPrivateKey = cleanBase64Key(privateKeyValue);
        byte[] privateKeyBytes = Base64.getDecoder().decode(cleanedPrivateKey);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        
        // Clean and decode public key
        String cleanedPublicKey = cleanBase64Key(publicKeyValue);
        byte[] publicKeyBytes = Base64.getDecoder().decode(cleanedPublicKey);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        logger.info("Successfully loaded RSA key pair from properties");
        return new KeyPair(publicKey, privateKey);
    }
    
    private String cleanBase64Key(String keyValue) {
        // Remove any whitespace, newlines, and common PEM headers/footers
        return keyValue
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
    }
    
    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            // Log the generated keys for adding to properties (for initial setup)
            if (!StringUtils.hasText(privateKeyValue)) {
                logGeneratedKeys(keyPair);
            }
            
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }
    
    private void logGeneratedKeys(KeyPair keyPair) {
        try {
            String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            
            logger.info("=== GENERATED RSA KEYS FOR APPLICATION.PROPERTIES ===");
            logger.info("Add these to your application.properties for persistent keys:");
            logger.info("auth.server.jwk.private-key={}", privateKeyBase64);
            logger.info("auth.server.jwk.public-key={}", publicKeyBase64);
            logger.info("====================================================");
        } catch (Exception e) {
            logger.error("Failed to log generated keys", e);
        }
    }
}