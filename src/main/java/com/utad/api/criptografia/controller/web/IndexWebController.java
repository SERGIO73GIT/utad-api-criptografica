package com.utad.api.criptografia.controller.web;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotBlank;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

@Controller
public class IndexWebController {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private static String secretKey = "utad";

    private static String salt = "desarrollo";

    @GetMapping("/")
    public String index(
            @RequestParam(name = "name", required = false, defaultValue = "World") String name,
            Model model) {
        model.addAttribute("name", HtmlUtils.htmlEscape(name));
        return "index.jsp";

    }

    @GetMapping("/encode64")
    public String getEncode(
            @RequestParam(name = "e1", required = true) @NotBlank String r1,
            Model model) {

        logger.info("Request: GET /encode64; p1: {}", r1);
        logger.info(r1);

        String encodeBytes = Base64.getEncoder().encodeToString((r1).getBytes());
        logger.info(encodeBytes);
        model.addAttribute("encode", HtmlUtils.htmlEscape(encodeBytes));

        return "practica1.jsp";

    }

    @GetMapping("/decode64")
    public String getDecode(
            @RequestParam(name = "d1", required = true) @NotBlank String d1,
            Model model) {

        logger.info("Request: GET /decode64; p1: {}", d1);
        logger.info(d1);

        byte[] decodedBytes = Base64.getDecoder().decode(d1);
        String decodedString = new String(decodedBytes);
        logger.info(decodedString);
        model.addAttribute("encode", HtmlUtils.htmlEscape(decodedString));

        return "practica1.jsp";

    }

    /**
     * @param h1
     * @param model
     * @return
     */
    @GetMapping("/hexhash")
    public String getHexHash(
            @RequestParam(name = "h1", required = true) @NotBlank String h1,
            Model model) {

        logger.info("Request: GET /hexhash; h1: {}", h1);
        logger.info(h1);

        String md5Hash = getHash(h1, "MD5");

        String sha1Hash = getHash(h1, "SHA-1");
        String sha256Hash = getHash(h1, "SHA-256");
        String sha512Hash = getHash(h1, "SHA-512");

        logger.info("md5Hash: " + md5Hash);
        logger.info("sha1Hash: " + sha1Hash);
        logger.info("sha256Hash: " + sha256Hash);
        logger.info("sha512Hash: " + sha512Hash);

        model.addAttribute("md5", HtmlUtils.htmlEscape(md5Hash));

        model.addAttribute("sha1", HtmlUtils.htmlEscape(sha1Hash));
        model.addAttribute("sha2", HtmlUtils.htmlEscape(sha256Hash));
        model.addAttribute("sha3", HtmlUtils.htmlEscape(sha512Hash));

        return "practica2.jsp";

    }

    private static String bytesToHex(
            byte[] hash) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String getHash(
            String message,
            String algorithm) {
        try {
            byte[] buffer = message.getBytes();
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(buffer);
            byte[] digest = md.digest();
            String hex = bytesToHex(digest);
            return hex;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param hash1
     * @param model
     * @return
     */
    @GetMapping("/unhash")
    public String getUnhash(
            @RequestParam(name = "hash1", required = true) @NotBlank String hash1,
            Model model) {

        logger.info("Request: GET /unhash; hash1: {}", hash1);
        logger.info(hash1);

        String md5Hash = getHash(hash1, "MD5");

        String sha1Hash = getHash(hash1, "SHA-1");
        String sha256Hash = getHash(hash1, "SHA-256");
        String sha512Hash = getHash(hash1, "SHA-512");

        logger.info("md5Hash: " + md5Hash);
        logger.info("sha1Hash: " + sha1Hash);
        logger.info("sha256Hash: " + sha256Hash);
        logger.info("sha512Hash: " + sha512Hash);

        model.addAttribute("md5", HtmlUtils.htmlEscape(md5Hash));

        model.addAttribute("sha1", HtmlUtils.htmlEscape(sha1Hash));
        model.addAttribute("sha2", HtmlUtils.htmlEscape(sha256Hash));
        model.addAttribute("sha3", HtmlUtils.htmlEscape(sha512Hash));

        return "practica2.jsp";

    }

    /**
     * @param aes1
     * @param model
     * @return
     */
    @GetMapping("/encryptaes")
    public String getEncrypt(
            @RequestParam(name = "aes1", required = true) @NotBlank String aes1,
            Model model) {

        logger.info("Request: GET /unhash; aes1: {}", aes1);
        logger.info(aes1);

        String encrypted = encrypt(aes1);
        String decrypted = decrypt(encrypted);

        logger.info("encrypt: " + encrypted);

        model.addAttribute("encrypted", HtmlUtils.htmlEscape(encrypted));
        model.addAttribute("decrypted", HtmlUtils.htmlEscape(decrypted));

        return "practica3.jsp";

    }

    private static String encrypt(
            String strToEncrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    private static String decrypt(
            String strToDecrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

}
