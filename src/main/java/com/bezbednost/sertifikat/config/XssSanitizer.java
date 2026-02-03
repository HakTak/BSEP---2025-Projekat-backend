package com.bezbednost.sertifikat.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.boot.jackson.JsonComponent;

import java.io.IOException;

// @JsonComponent govori Springu da automatski registruje ovu klasu
// i koristi je za SVE Stringove koji stižu kroz JSON
@JsonComponent
public class XssSanitizer extends JsonDeserializer<String> {

    @Override
    public String deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        // 1. Pročitaj originalni string koji je stigao sa Frontenda
        String input = p.getText();

        if (input == null) {
            return null;
        }

        // 2. Očisti ga pomoću Jsoup-a
        // Safelist.none() znači: "Ukloni SVE HTML tagove".
        // Ako želiš da dozvoliš npr. bold (<b>), koristi Safelist.basic()
        return Jsoup.clean(input, Safelist.none());
    }
}