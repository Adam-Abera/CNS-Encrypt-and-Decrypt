package com.example.googleOAuth;



import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Map;
//AES example plain text: Two One Nine Two
//AES example key: Thats my Kung Fu
//3DES example key: 9mng65v8jf4lxn93nabf981m
public class MainClass {
    JButton encrypt;
    JButton decrypt;
    JComboBox algo;
    JTextField plainText;
    JTextField cipherText;
    JTextField encryptKey;
    JTextField decryptKey;
    JTextField encryptResult;
    JTextField decryptResult;
    static MainClass mClass;
    public MainClass()
    {
        JFrame frame = new JFrame("Encryption and Decryption");
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        Container container = frame.getContentPane();
        container.setLayout(new GridLayout(1,2));
        JPanel encryptPanel = new JPanel(new GridLayout(6,1));
        JPanel ePanel = new JPanel(new FlowLayout());
        JPanel dPanel = new JPanel(new FlowLayout());
        JPanel algoPanel = new JPanel(new FlowLayout());
        JPanel decryptPanel = new JPanel(new GridLayout(6,1));
        plainText = new JTextField();
        cipherText = new JTextField();
        encryptKey = new JTextField();
        encryptKey.setPreferredSize(new Dimension(200,35));
        decryptKey = new JTextField();
        decryptKey.setPreferredSize(new Dimension(200,35));
        JLabel eKey = new JLabel("Encryption Key");
        JLabel dKey = new JLabel("Decryption Key");
        encrypt = new JButton("Encrypt");
        encrypt.setBackground(Color.BLUE);
        encrypt.setForeground(Color.WHITE);
        encrypt.setPreferredSize(new Dimension(100, 35));
        encrypt.addActionListener(new Listener());
        JPanel eButtonPanel = new JPanel(new FlowLayout());
        decrypt = new JButton("Decrypt");
        decrypt.addActionListener(new Listener());
        decrypt.setBackground(Color.RED);
        decrypt.setForeground(Color.WHITE);
        decrypt.setPreferredSize(new Dimension(100, 35));
        JPanel dButtonPanel = new JPanel(new FlowLayout());
        String[] algos = {"OTP","3DES","AES"};
        algo = new JComboBox(algos);
        JLabel algoLabel = new JLabel("Algorithm:");
        JLabel pTextLabel = new JLabel("Enter plain text(to be encrypted)");
        pTextLabel.setHorizontalAlignment(SwingConstants.CENTER);
        JLabel cTextLabel = new JLabel("Enter cipher text(to be decrypted)");
        cTextLabel.setHorizontalAlignment(SwingConstants.CENTER);
        encryptResult = new JTextField();
        encryptResult.setEditable(false);
        decryptResult = new JTextField();
        decryptResult.setEditable(false);
        encryptPanel.add(pTextLabel);
        encryptPanel.add(plainText);
        ePanel.add(eKey);
        ePanel.add(encryptKey);
        encryptPanel.add(ePanel);
        eButtonPanel.add(encrypt);
        encryptPanel.add(eButtonPanel);
        encryptPanel.add(encryptResult);
        algoPanel.add(algoLabel);
        algoPanel.add(algo);
        encryptPanel.add(algoPanel);

        decryptPanel.add(cTextLabel);
        decryptPanel.add(cipherText);
        dPanel.add(dKey);
        dPanel.add(decryptKey);
        decryptPanel.add(dPanel);
        dButtonPanel.add(decrypt);
        decryptPanel.add(dButtonPanel);
        decryptPanel.add(decryptResult);

        container.add(encryptPanel);
        container.add(decryptPanel);
        frame.setSize(600,480);
        frame.setLocation(383,150);
        frame.setVisible(true);
    }
    public static void main(String[] args)
    {
        mClass = new MainClass();
    }
    public static void callMain()
    {
        main(new String[]{"hello"});
    }
    static int XOR(int a, int b)
    {
        if((a == 0 && b==1) || (a ==1 && b == 0))
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    class Listener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            String algoText = (String) algo.getSelectedItem();
            String pText = plainText.getText();
            String cText = cipherText.getText();
            String e_Key = encryptKey.getText();
            String d_Key = decryptKey.getText();
            int bin_e_result = 0;
            String e_result1 = "";
            String e_result = "";
            String d_result = "";
            int bin_d_result = 0;
            String d_result1 = "";
            String binary_e_key = "";
            String binary_e_key1 = "";
            byte[] encrypted_pText;
            if (e.getSource() == encrypt)
            {
                if(algoText.equals("OTP"))
                {
                    try {
                        if (pText.length() == e_Key.length()) {
                            for (int i = 0; i < pText.length(); i++) {
                                String a = Integer.toBinaryString(pText.toCharArray()[i]);
                                String b = Integer.toBinaryString(e_Key.toCharArray()[i]);
                                e_result1 = "0";
                                binary_e_key1 = "0";
                                binary_e_key1 += b;
                                for (int j = 0; j < a.length(); j++)
                                {
                                    int c = XOR(Integer.parseInt("" + a.toCharArray()[j]),
                                            Integer.parseInt("" + b.toCharArray()[j]));
                                    System.out.println(i + " " +
                                            Integer.parseInt("" + a.toCharArray()[j]) + " "
                                            + Integer.parseInt("" + a.toCharArray()[j]) + "=" + c);

                                    e_result1 += c;
                                }
                                System.out.println("--------------------------------------");
                                e_result += e_result1;
                                binary_e_key += binary_e_key1;
                                if(i<pText.length()-1)
                                {
                                    e_result += " ";
                                    binary_e_key += " ";
                                }
                            }
                            encryptResult.setText(e_result);
                            System.out.println(e_result);
                            decryptKey.setText(binary_e_key);
                        } else {
                            JOptionPane.showMessageDialog(mClass.encryptKey, "The plain text and " +
                                    "key's length must be equal! Check if there are spaces at the beginning or" +
                                    "end of the plain text and key. Remove them if found");
                        }
                    }
                    catch(Exception ex)
                    {
                        JOptionPane.showMessageDialog(mClass.encryptKey, "Not a valid key");
                    }
                }
                if(algoText.equals("3DES"))
                {
                    byte[] e_Key12 = e_Key.getBytes();
                    SecretKeySpec secretKeySpec = new SecretKeySpec(e_Key12, "TripleDES");
                    byte[] iv = "a76nb5h9".getBytes();
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    try
                    {
                        Cipher encryptCipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
                        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
                        byte[] pTextBytes = cText.getBytes(StandardCharsets.UTF_8);
                        encrypted_pText = encryptCipher.doFinal(pTextBytes);
                        encryptResult.setText(encrypted_pText.toString());
                    }
                    catch (Exception ex)
                    {
                        JOptionPane.showMessageDialog(mClass.encryptKey, "Error encountered." +
                                ex.getMessage());
                    }

                }
                if(algoText.equals("AES"))
                {
                    String input = pText;
                    String password = e_Key;
                    String salt = "aaitaes!";
                    IvParameterSpec ivParameterSpec = MainClass.generateIv();
                    try {
                        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
                        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                                .getEncoded(), "AES");
                        String algorithm = "AES/CBC/PKCS5Padding";
                        String cipherText = MainClass.encrypt(algorithm, input, secret, ivParameterSpec);
                        encryptResult.setText(cipherText);
                    }
                    catch (Exception ex)
                    {
                        JOptionPane.showMessageDialog(mClass.encryptKey, "Error encountered." +
                                ex.getMessage());
                    }
                }
            }

            if (e.getSource() == decrypt)
            {
                if(algoText.equals("OTP"))
                {
                    String bit1 = cText.replace(" ", "");
                    String bit2 = d_Key.replace(" ", "");
                    //int n = d_Key.length();
                    try {
                        if (cText.length() == d_Key.length())
                        {
                            System.out.println(bit1.length()/8);
                            for (int i = 0; i < (bit1.length()/8); i++) {
                                d_result1 = "";
                                for (int j = i*8; j < (i+1)*8; j++)
                                {
                                    int c = XOR(Integer.parseInt("" + bit1.toCharArray()[j]),
                                            Integer.parseInt("" + bit2.toCharArray()[j]));
                                    System.out.println(i + " " +
                                            Integer.parseInt("" + bit1.toCharArray()[j]) + " "
                                            + Integer.parseInt("" + bit2.toCharArray()[j]) + "=" + c);

                                    d_result1 += c;
                                }
                                System.out.println("--------------------------------------");
                                d_result += binaryToChar(d_result1);
                            }
                            decryptResult.setText(d_result);
                            System.out.println(d_result);
                        } else {
                            JOptionPane.showMessageDialog(mClass.decryptKey, "The plain text and " +
                                    "key's length must be equal! Cipher text and key must be in binary, " +
                                    "and have the same length. Check if there are spaces at the beginning or" +
                                    "end of the plain text and key. Remove them if found");
                        }
                    }
                    catch(Exception ex)
                    {
                        JOptionPane.showMessageDialog(mClass.decryptKey, "Not a valid key. The " +
                                "cipher text and key must be in binary, and have the same length."+
                                ex.getMessage());
                    }
                }
                if(algoText.equals("3DES"))
                {
                    try
                    {
                        byte[] d_Key12 = d_Key.getBytes();
                        byte[] iv = "a76nb5h9".getBytes();
                        IvParameterSpec ivSpec = new IvParameterSpec(iv);
                        Cipher decryptCipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
                        SecretKeySpec secretKeySpec = new SecretKeySpec(d_Key12, "TripleDES");
                        decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
                        byte[] decrypted_Bytes = decryptCipher.doFinal(cText.getBytes());
                        String decryptedMessage = new String(decrypted_Bytes, StandardCharsets.UTF_8);
                        decryptResult.setText(decryptedMessage);
                    }
                    catch (Exception ex)
                    {
                        JOptionPane.showMessageDialog(mClass.decryptKey, "Error encountered." +
                                ex.getMessage());
                    }
                }
                if(algoText.equals("AES"))
                {
                    String input = cText;
                    String password = d_Key;
                    String salt = "aaitaes!";
                    IvParameterSpec ivParameterSpec = MainClass.generateIv();
                    try
                    {
                        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
                        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                                .getEncoded(), "AES");
                        String algorithm = "AES/CBC/PKCS5Padding";
                        String plainText = MainClass.decrypt(algorithm, input, secret, ivParameterSpec);
                        decryptResult.setText(plainText);
                    }
                    catch (Exception ex)
                    {
                        JOptionPane.showMessageDialog(mClass.encryptKey, "Error encountered." +
                                ex.getMessage());
                    }
                }
            }
        }
    }
    public static IvParameterSpec generateIv()
    {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    public static String encrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException
    {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }
    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }
    static char binaryToChar(String binary)
    {
        int result = 0;
        char a = ' ';
        for (int j = 0; j < 8; j++)
        {
            result += (int) (Integer.parseInt(String.valueOf(binary.toCharArray()[j])) * Math.pow(2, 7 - j));
        }
        a = (char) result;
        System.out.println(a + ": " + result );
        return a;
    }
}
