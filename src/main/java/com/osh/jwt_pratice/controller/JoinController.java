package com.osh.jwt_pratice.controller;

import com.osh.jwt_pratice.dto.JoinDTO;
import com.osh.jwt_pratice.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(@RequestBody JoinDTO joinDTO) {

        joinService.joinProcess(joinDTO);

        return "ok";
    }

}
