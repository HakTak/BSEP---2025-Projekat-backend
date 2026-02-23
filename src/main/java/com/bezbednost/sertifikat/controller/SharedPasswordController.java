package com.bezbednost.sertifikat.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bezbednost.sertifikat.model.ShareEntry;
import com.bezbednost.sertifikat.service.SharedPasswordService;

@RestController
@RequestMapping("/api/passwordManager")
public class SharedPasswordController {
	
	@Autowired
	private SharedPasswordService sharedPasswordService;

	@GetMapping("/getUserShareEntries")
	public ResponseEntity<?> getShareEntriesForUser(){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        org.springframework.security.oauth2.jwt.Jwt jwt = (Jwt) authentication.getPrincipal();
        return ResponseEntity.ok(sharedPasswordService.getShareEntriesForUser(jwt.getClaimAsString("email")));
	}
	
	@PostMapping("/createShareEntry")
	public ResponseEntity<?> create(@RequestBody ShareEntry shareEntriy){
		return ResponseEntity.ok(sharedPasswordService.create(shareEntriy));
	}
	
}
