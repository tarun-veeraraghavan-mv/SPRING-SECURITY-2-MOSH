package com.security.v2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.ConfigurableEnvironment;

import me.paulschwarz.springdotenv.DotenvPropertySource;

@SpringBootApplication
public class V2Application {

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(V2Application.class);
		app.addInitializers(applicationContext -> {
			ConfigurableEnvironment env = applicationContext.getEnvironment();
			DotenvPropertySource.addToEnvironment(env);
		});
		app.run(args);
	}

}
