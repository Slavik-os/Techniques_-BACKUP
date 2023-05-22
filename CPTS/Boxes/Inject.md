![[Pasted image 20230329110445.png]]

# Nmap
```shell
	PORT     STATE SERVICE     VERSION
	
	22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
	
	| ssh-hostkey: 
	
	|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
	
	|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
	
	|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
	
	8080/tcp open  nagios-nsca Nagios NSCA
	
	|_http-title: Home
	
	| http-methods: 
	
	|_  Supported Methods: GET HEAD OPTIONS
	
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Web server enumeration

1. Backend : based on 404 error page and after some googeling , the webserver seems running java SpringBoot .
![[Pasted image 20230329113426.png]]

# Gobuster
![[Pasted image 20230329115349.png]]


# LFI

/upload only accept images, however after submiting our image, 
![[Pasted image 20230329120815.png]]
we are greated with a link to view the image we uploaded
![[Pasted image 20230329120848.png]]
playing with the img parameter on BurpSuite we get an LFI

![[Pasted image 20230329120939.png]]

# Foothold
After some googling and hints POM.xml is what we need to look for, using curl the error leaks the full path of our application
![[Pasted image 20230329122732.png]]
Mostly the POM.xml file is located in the root application direcotry so that'll be /var/www/WebApp/, ../../../pom.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version> /* Patched not vuln */
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```


