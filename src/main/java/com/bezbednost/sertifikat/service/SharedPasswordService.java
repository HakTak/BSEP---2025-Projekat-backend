package com.bezbednost.sertifikat.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.bezbednost.sertifikat.dto.ShareEntryDTO;
import com.bezbednost.sertifikat.model.PasswordEntry;
import com.bezbednost.sertifikat.model.ShareEntry;
import com.bezbednost.sertifikat.repository.ShareEntryRepository;

@Service
public class SharedPasswordService {

	
	@Autowired
	private ShareEntryRepository shareEntryRepository;
	
	
	
	
	public List<ShareEntryDTO> getShareEntriesForUser(String email) {
	    List<ShareEntry> allShares = shareEntryRepository.findAll(); // or a smarter query
	    
	    return allShares.stream()
	        .filter(share -> share.getPasswordEntries().stream()
	            .anyMatch(pe -> pe.getEmail().equals(email)))
	        .map(share -> {
	            PasswordEntry myEntry = share.getPasswordEntries().stream()
	                .filter(pe -> pe.getEmail().equals(email))
	                .findFirst().get();
	            
	            ShareEntryDTO dto = new ShareEntryDTO();
	            dto.setId(share.getId());
	            dto.setSiteName(share.getSiteName());
	            dto.setUserName(share.getUserName());
	            dto.setOwner(share.getOwner());
	            dto.setEncryptedPassword(myEntry.getEncryptedPassword());
	            return dto;
	        })
	        .collect(Collectors.toList());
	}
	
	public ShareEntry create(ShareEntry shareEntry) {
		return shareEntryRepository.save(shareEntry);
	}
}
