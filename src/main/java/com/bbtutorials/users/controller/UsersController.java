package com.bbtutorials.users.controller;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bbtutorials.users.asymmEncryption.EncryptAsymmetric;
import com.bbtutorials.users.asymmEncryption.DecryptAsymmetric;
import com.bbtutorials.users.entity.Users;
import com.bbtutorials.users.links.UserLinks;
import com.bbtutorials.users.service.UsersService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/")
public class UsersController {
	
	@Autowired
	UsersService usersService;

    @Autowired
    EncryptAsymmetric encAs;

    @Autowired
    DecryptAsymmetric decAs;
	
	@GetMapping(path = UserLinks.LIST_USERS)
    public ResponseEntity<?> listUsers() throws IOException, GeneralSecurityException {
        log.info("UsersController:  list users");
        List<Users> resource = usersService.getUsers();
        for (int i = 0; i < resource.size(); i++) {
                   	 
                   	String decEmail = decAs.decryptAsymmetric(resource.get(i).getEmail());
                   	resource.get(i).setEmail(decEmail);
                   }
        return ResponseEntity.ok(resource);
    }
	
	@PostMapping(path = UserLinks.ADD_USER)
	public ResponseEntity<?> saveUser(@RequestBody Users user) throws IOException, GeneralSecurityException {
        log.info("UsersController:  list users");

// here

String encEmail= encAs.encryptAsymmetric(user.getEmail());
user.setEmail(encEmail);

// here

        Users resource = usersService.saveUser(user);
        return ResponseEntity.ok(resource);
    }
}
