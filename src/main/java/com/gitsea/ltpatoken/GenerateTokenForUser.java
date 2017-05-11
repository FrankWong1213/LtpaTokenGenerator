package com.gitsea.ltpatoken;

import java.util.Date;

import domino.LtpaToken;


public class GenerateTokenForUser {
	public static void main(String[] args) {
		String userName = "test";//用户名
		Date now = new Date();
		LtpaToken generate = LtpaToken.generate(userName, now, new Date(now.getTime() + 86400000L));
		System.out.println(generate.getLtpaToken());
		generate =  new LtpaToken("");
		System.out.println(generate.getUser());
		System.out.println(generate.isValid());
	}
}
