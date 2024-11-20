package com.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import javax.swing.*;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Java21版本运行无误
 */
public class AES256FileEncryptor {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;
    private static final byte[] ENCRYPTION_MARKER = "ENCRYPTED".getBytes();
    private static Timer timer;
    private static int countdown = 60;
    private static JLabel countdownLabel;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(AES256FileEncryptor::createAndShowGUI);
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("AES256 文件加密/解密工具");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(500, 400);
        frame.setLayout(new GridBagLayout());

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.insets = new Insets(10, 10, 10, 10);
        constraints.fill = GridBagConstraints.HORIZONTAL;

        // 密码标签和密码框
        JLabel passwordLabel = new JLabel("密码:");
        constraints.gridx = 0;
        constraints.gridy = 0;
        frame.add(passwordLabel, constraints);

        JPasswordField passwordField = new JPasswordField(20);
        constraints.gridx = 1;
        frame.add(passwordField, constraints);

        passwordField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }
        });

        // 确认密码标签和密码框
        JLabel confirmPasswordLabel = new JLabel("确认密码:");
        constraints.gridx = 0;
        constraints.gridy = 1;
        frame.add(confirmPasswordLabel, constraints);

        JPasswordField confirmPasswordField = new JPasswordField(20);
        constraints.gridx = 1;
        frame.add(confirmPasswordField, constraints);

        confirmPasswordField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }
        });

        // 清空密码按钮
        JButton clearButton = new JButton("清空密码");
        constraints.gridx = 2;
        frame.add(clearButton, constraints);

        clearButton.addActionListener(e -> {
            passwordField.setText("");
            confirmPasswordField.setText("");
            resetTimer();
        });

        // 倒计时显示标签
        countdownLabel = new JLabel("60 秒后自动清空密码");
        constraints.gridx = 1;
        constraints.gridy = 2;
        frame.add(countdownLabel, constraints);

        startTimer(passwordField, confirmPasswordField);

        // 选择目录按钮和文本框
        JLabel directoryLabel = new JLabel("目录路径:");
        constraints.gridx = 0;
        constraints.gridy = 3;
        frame.add(directoryLabel, constraints);

        JTextField directoryPathField = new JTextField(20);
        constraints.gridx = 1;
        frame.add(directoryPathField, constraints);

        directoryPathField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                resetTimer();
            }
        });

        JButton browseButton = new JButton("浏览...");
        constraints.gridx = 2;
        frame.add(browseButton, constraints);

        browseButton.addActionListener(e -> {
            JFileChooser directoryChooser = new JFileChooser();
            directoryChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int result = directoryChooser.showOpenDialog(frame);
            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedDirectory = directoryChooser.getSelectedFile();
                directoryPathField.setText(selectedDirectory.getAbsolutePath());
                resetTimer();
            }
        });

        // 加密/解密选项
        JRadioButton encryptButton = new JRadioButton("加密");
        JRadioButton decryptButton = new JRadioButton("解密");
        encryptButton.setSelected(true);
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(encryptButton);
        modeGroup.add(decryptButton);

        constraints.gridx = 0;
        constraints.gridy = 4;
        frame.add(encryptButton, constraints);

        constraints.gridx = 1;
        frame.add(decryptButton, constraints);

        encryptButton.addActionListener(e -> resetTimer());
        decryptButton.addActionListener(e -> resetTimer());

        // 开始按钮
        JButton startButton = new JButton("开始");
        constraints.gridx = 1;
        constraints.gridy = 5;
        frame.add(startButton, constraints);

        startButton.addActionListener(e -> {
            String password = new String(passwordField.getPassword());
            String confirmPassword = new String(confirmPasswordField.getPassword());
            if (password.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "密码不能为空。", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (confirmPassword.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "密码不能为空。", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String dirPath = directoryPathField.getText();
            boolean isEncrypt = encryptButton.isSelected();

            if (!password.equals(confirmPassword)) {
                JOptionPane.showMessageDialog(frame, "两次输入的密码不匹配。", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (dirPath == null || dirPath.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "请选择一个有效的目录。", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                if (isEncrypt) {
                    encryptDirectory(password, dirPath);
                    JOptionPane.showMessageDialog(frame, "加密操作成功完成。", "成功", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    decryptDirectory(password, dirPath);
                    JOptionPane.showMessageDialog(frame, "解密操作成功完成。", "成功", JOptionPane.INFORMATION_MESSAGE);
                }
                //清除密码
//                passwordField.setText("");
//                confirmPasswordField.setText("");
                resetTimer();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
            }
        });

        frame.setVisible(true);
    }

    private static void startTimer(JPasswordField passwordField, JPasswordField confirmPasswordField) {
        timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (countdown > 0) {
                    countdown--;
                    SwingUtilities.invokeLater(() -> countdownLabel.setText(countdown + " 秒后自动清空密码"));
                } else {
                    SwingUtilities.invokeLater(() -> {
                        passwordField.setText("");
                        confirmPasswordField.setText("");
                        countdown = 60;
                        countdownLabel.setText(countdown + " 秒后自动清空密码");
                    });
                    timer.cancel();
                }
            }
        }, 0, 1000);
    }

    private static void resetTimer() {
        if (timer != null) {
            timer.cancel();
        }
        countdown = 60;
        countdownLabel.setText(countdown + " 秒后自动清空密码");
        startTimer(null, null);
    }

    // 加密目录中的所有文件，包括子目录
    public static void encryptDirectory(String password, String dirPath) throws Exception {
        processDirectory(password, dirPath, true);
    }

    // 解密目录中的所有文件，包括子目录
    public static void decryptDirectory(String password, String dirPath) throws Exception {
        processDirectory(password, dirPath, false);
    }

    // 处理目录中的文件，加密或解密
    private static void processDirectory(String password, String dirPath, boolean encrypt) throws Exception {
        SecretKeySpec keySpec = getKeyFromPassword(password);

        File dir = new File(dirPath);
        if (!dir.isDirectory()) {
            throw new IllegalArgumentException("无效的目录路径。");
        }

        processFilesRecursively(dir, keySpec, encrypt);
    }

    // 递归处理目录中的文件
    private static void processFilesRecursively(File dir, SecretKeySpec keySpec, boolean encrypt) throws Exception {
        for (File file : dir.listFiles()) {
            if (file.isDirectory()) {
                processFilesRecursively(file, keySpec, encrypt);
            } else if (file.isFile()) {
                Path filePath = file.toPath();
                if (encrypt) {
                    if (isFileEncrypted(filePath)) {
                        System.out.println("文件已加密，跳过: " + filePath);
                        continue;
                    }
                    System.out.println("正在加密文件: " + filePath);
                    encryptFile(filePath, keySpec);
                    System.out.println("加密完成: " + filePath);
                } else {
                    System.out.println("正在解密文件: " + filePath);
                    try {
                        decryptFile(filePath, keySpec);
                        System.out.println("解密完成: " + filePath);
                    } catch (Exception e) {
                        System.out.println("文件已解密/密码错误，跳过: " + filePath);
                    }
                }
            }
        }
    }

    // 根据密码生成密钥
    private static SecretKeySpec getKeyFromPassword(String password) throws Exception {
        byte[] keyBytes = new byte[KEY_SIZE / 8];
        byte[] passwordBytes = password.getBytes("UTF-8");
        System.arraycopy(passwordBytes, 0, keyBytes, 0, Math.min(passwordBytes.length, keyBytes.length));
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    // 加密文件
    private static void encryptFile(Path filePath, SecretKeySpec keySpec) throws Exception {
        byte[] iv = generateIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] fileBytes = Files.readAllBytes(filePath);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        try (FileOutputStream outputStream = new FileOutputStream(filePath.toFile())) {
            outputStream.write(ENCRYPTION_MARKER);
            outputStream.write(iv);
            outputStream.write(encryptedBytes);
        }
    }

    // 解密文件
    private static void decryptFile(Path filePath, SecretKeySpec keySpec) throws Exception {
        byte[] fileBytes = Files.readAllBytes(filePath);
        if (fileBytes.length < ENCRYPTION_MARKER.length + IV_SIZE) {
            throw new IllegalArgumentException("无效的加密文件。");
        }

        // 检查文件是否有加密标记
        for (int i = 0; i < ENCRYPTION_MARKER.length; i++) {
            if (fileBytes[i] != ENCRYPTION_MARKER[i]) {
                throw new IllegalArgumentException("文件没有加密标记，无法解密。");
            }
        }

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(fileBytes, ENCRYPTION_MARKER.length, iv, 0, IV_SIZE);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] encryptedBytes = new byte[fileBytes.length - ENCRYPTION_MARKER.length - IV_SIZE];
        System.arraycopy(fileBytes, ENCRYPTION_MARKER.length + IV_SIZE, encryptedBytes, 0, encryptedBytes.length);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        try (FileOutputStream outputStream = new FileOutputStream(filePath.toFile())) {
            outputStream.write(decryptedBytes);
        }
    }

    // 生成随机的IV
    private static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // 检查文件是否已加密，通过检查文件头标识符
    private static boolean isFileEncrypted(Path filePath) {
        try {
            byte[] fileBytes = Files.readAllBytes(filePath);
            if (fileBytes.length < ENCRYPTION_MARKER.length) {
                return false;
            }
            // Check if the first bytes match the encryption marker
            for (int i = 0; i < ENCRYPTION_MARKER.length; i++) {
                if (fileBytes[i] != ENCRYPTION_MARKER[i]) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
