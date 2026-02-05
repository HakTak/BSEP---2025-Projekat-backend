package com.bezbednost.sertifikat.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    
    @Autowired
    private JavaMailSender mailSender;
    
    @Value("${spring.mail.username}")
    private String fromEmail;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    public void sendActivationEmail(String toEmail, String firstName, String activationToken) {
        String activationLink = frontendUrl + "/activate?token=" + activationToken;
        
        String subject = "Aktivacija nalog - BSEP Sertifikat";
        
        String body = "Pozdrav " + firstName + ",\n\n" +
                "Hvala što ste se registrovali! Kliknite na link ispod da aktivirate svoj nalog:\n\n" +
                activationLink + "\n\n" +
                "Link je validan 24 sata.\n\n" +
                "Ako niste koristili login, ignorišite ovaj email.\n\n" +
                "Srdačno,\n" +
                "BSEP Tim";
        
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(body);
        
        try {
            mailSender.send(message);
        } catch (Exception e) {
            throw new RuntimeException("Greška pri slanju email-a: " + e.getMessage());
        }
    }
    public void sendCACredentials(String to, String firstName, String password) {
        String subject = "Dobrodošli u PKI Sistem - Vaši podaci za pristup";
        String text = "Poštovani " + firstName + ",\n\n" +
                "Administrator vas je registrovao kao CA korisnika.\n" +
                "Vaša privremena lozinka je: " + password + "\n\n" +
                "Molimo vas da se prijavite na sistem. Prilikom prvog pristupa bićete obavezni da promenite ovu lozinku.\n\n" +
                "Srdačan pozdrav,\nPKI Tim";

        // Poziv tvoje postojeće metode za slanje mejla (sendSimpleMessage ili slično)
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);

        try {
            mailSender.send(message);
        } catch (Exception e) {
            throw new RuntimeException("Greška pri slanju email-a: " + e.getMessage());
        }
    }
    
    public void sendPasswordResetEmail(String toEmail, String firstName, String resetToken) {
        String resetLink = frontendUrl + "/reset-password?token=" + resetToken;
        
        String subject = "Oporavak lozinke - BSEP Sertifikat";
        
        String body = "Pozdrav " + firstName + ",\n\n" +
                "Primili ste zahtev za oporavak lozinke. Kliknite na link ispod da resetujete vašu lozinku:\n\n" +
                resetLink + "\n\n" +
                "Link je validan 24 sata.\n\n" +
                "Ako niste zahtevali reset lozinke, ignorišite ovaj email.\n\n" +
                "Srdačno,\n" +
                "BSEP Tim";
        
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(body);
        
        try {
            mailSender.send(message);
        } catch (Exception e) {
            throw new RuntimeException("Greška pri slanju email-a: " + e.getMessage());
        }
    }
}
