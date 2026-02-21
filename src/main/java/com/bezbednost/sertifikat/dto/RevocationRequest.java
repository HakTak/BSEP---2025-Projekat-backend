package com.bezbednost.sertifikat.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RevocationRequest {
	private String serialNumber;
	private int revocationCode;
}
