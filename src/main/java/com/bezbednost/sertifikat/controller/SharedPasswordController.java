package com.bezbednost.sertifikat.controller;

import com.bezbednost.sertifikat.model.ShareEntry;
import com.bezbednost.sertifikat.service.AuditEventType;
import com.bezbednost.sertifikat.service.AuditLogger;
import com.bezbednost.sertifikat.service.SharedPasswordService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/passwordManager")
public class SharedPasswordController {

	@Autowired
	private SharedPasswordService sharedPasswordService;

	@Autowired
	private AuditLogger auditLogger;

	@GetMapping("/getUserShareEntries")
	public ResponseEntity<?> getShareEntriesForUser(HttpServletRequest httpRequest) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Jwt jwt = (Jwt) authentication.getPrincipal();
		String email = jwt.getClaimAsString("email");
		String ip    = getClientIp(httpRequest);

		auditLogger.logSuccess(AuditEventType.PASSWORD_ENTRY_VIEW, email, ip,
				"Korisnik pregledao svoje password manager unose");

		return ResponseEntity.ok(sharedPasswordService.getShareEntriesForUser(email));
	}

	@PostMapping("/createShareEntry")
	public ResponseEntity<?> create(
			@RequestBody ShareEntry shareEntry,
			HttpServletRequest httpRequest) {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Jwt jwt = (Jwt) authentication.getPrincipal();
		String email = jwt.getClaimAsString("email");
		String ip    = getClientIp(httpRequest);

		try {
			Object result = sharedPasswordService.create(shareEntry);
			auditLogger.logSuccess(AuditEventType.PASSWORD_ENTRY_CREATE, email, ip,
					"Kreiran novi password entry. Sajt=" + shareEntry.getSiteName()
							+ " | vlasnik=" + shareEntry.getOwner());
			return ResponseEntity.ok(result);
		} catch (Exception e) {
			auditLogger.logFailure(AuditEventType.PASSWORD_ENTRY_CREATE, email, ip,
					"Neuspesno kreiranje password entry-ja: " + e.getMessage());
			throw e;
		}
	}

	private String getClientIp(HttpServletRequest request) {
		String xff = request.getHeader("X-Forwarded-For");
		if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
		return request.getRemoteAddr();
	}
}