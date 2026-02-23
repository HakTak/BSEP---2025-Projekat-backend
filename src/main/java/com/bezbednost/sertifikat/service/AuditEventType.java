package com.bezbednost.sertifikat.service;

/**
 * Tipovi bezbednosnih dogadjaja koji se loguju u audit log.
 * Pokriva sve dogadjaje iz specifikacije za neporecivost.
 */
public enum AuditEventType {

    // --- Autentifikacija i upravljanje nalogom ---
    USER_REGISTER,
    USER_ACTIVATE_ACCOUNT,
    USER_ACTIVATE_ACCOUNT_FAIL,
    USER_FORGOT_PASSWORD,
    USER_RESET_PASSWORD,
    USER_CHANGE_PASSWORD,
    USER_UPDATE_PROFILE,
    USER_DELETE,

    // --- CA korisnik kreiranje (admin akcija) ---
    ADMIN_CREATE_CA_USER,
    ADMIN_CREATE_CA_CERT,

    // --- Sesije ---
    SESSION_CREATED,
    SESSION_REVOKED,
    SESSION_BLOCKED_REVOKED,  // Pokusaj pristupa sa opozvanjem tokenom
    USER_LOGOUT,

    // --- Sertifikati ---
    CERT_ISSUE_ROOT,
    CERT_ISSUE_ROOT_FAIL,
    CERT_ISSUE_INTERMEDIATE,
    CERT_ISSUE_INTERMEDIATE_FAIL,
    CERT_ISSUE_EE,
    CERT_ISSUE_EE_FAIL,
    CERT_REVOKE,
    CERT_REVOKE_FAIL,
    CERT_DOWNLOAD,
    CERT_DOWNLOAD_FAIL,
    CERT_VALIDATE,
    CERT_VIEW_ALL,

    // --- CSR ---
    CSR_SUBMIT,
    CSR_SUBMIT_FAIL,
    CSR_APPROVE,
    CSR_APPROVE_FAIL,

    // --- Sabloni ---
    TEMPLATE_CREATE,
    TEMPLATE_VIEW,

    // --- Password manager ---
    PASSWORD_ENTRY_CREATE,
    PASSWORD_ENTRY_VIEW,

    // --- Pristup ---
    ACCESS_DENIED,              // 403 – neautorizovani pristup
    UNAUTHORIZED_REQUEST,       // 401 – sesija istekla / opozva

    // --- Opste greske ---
    SYSTEM_ERROR
}