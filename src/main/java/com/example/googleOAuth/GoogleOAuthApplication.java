package com.example.googleOAuth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.EventListener;

import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@SpringBootApplication
public class GoogleOAuthApplication {

	public static void main(String[] args) {
		//web(Controller.a);
		//Controller.a += 1;
		//SpringApplication.run(GoogleOAuthApplication.class, args);
		SpringApplicationBuilder builder = new SpringApplicationBuilder(GoogleOAuthApplication.class);

		builder.headless(false);

		ConfigurableApplicationContext context = builder.run(args);
	}
	@EventListener(ApplicationReadyEvent.class)
	public void doSomethingAfterStartup() {
		browse("http://localhost:8080");
//		try {
//			URI uri = new URI("http://localhost:8080");
//			java.awt.Desktop.getDesktop().browse(uri);
//		} catch (Exception e) {
//			System.out.println(e.getMessage());
//		}
	}
	public static void browse(String url) {
		if (Desktop.isDesktopSupported()) {
			Desktop desktop = Desktop.getDesktop();
			try {
				desktop.browse(new URI(url));
			} catch (IOException | URISyntaxException e) {
				System.out.println(e.getMessage());
			}
		} else {
			Runtime runtime = Runtime.getRuntime();
			try {
				runtime.exec("rundll32 url.dll,FileProtocolHandler " + url);
			} catch (IOException e) {
				System.out.println(e.getMessage());
			}
		}
	}
}
