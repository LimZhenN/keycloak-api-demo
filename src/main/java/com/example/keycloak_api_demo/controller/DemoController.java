package com.example.keycloak_api_demo.controller;

import java.util.Map;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
public class DemoController {
	
	@GetMapping("/public/ping")
	public String pub() {
		return "pong (public)";
	}
	
	@GetMapping("/user/profile")
	public Map<String, Object> profile(JwtAuthenticationToken auth) {
		// return the user information and the authorities / roles from the API
		return Map.of("user", auth.getName(),"authories", auth.getAuthorities());
	}
	
	@GetMapping("/admin/metrics")
	public String admin() {
		return "Something that only admin can see";
			
		}
	
	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {
		try {
			request.logout(); // 让 Servlet 容器清理 session
			} catch (ServletException e) {
		        e.printStackTrace();
		    }
		    return "redirect:/login?logout"; // 回到登录页
		}
	
	}


