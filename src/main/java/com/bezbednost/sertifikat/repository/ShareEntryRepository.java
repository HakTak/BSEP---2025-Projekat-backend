package com.bezbednost.sertifikat.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bezbednost.sertifikat.model.ShareEntry;

public interface ShareEntryRepository extends JpaRepository<ShareEntry, Long> {

}
