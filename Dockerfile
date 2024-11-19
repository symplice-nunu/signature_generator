# Start with an appropriate Java image
FROM openjdk:23-jdk

# Set the working directory inside the container
WORKDIR /app

CMD ["mvn","clean","package"]
# Copy the Spring Boot JAR into the container
COPY target/signature_generator-0.0.1-SNAPSHOT.jar app.jar

# Expose port 8080 for the Spring Boot app
EXPOSE 8080

# Run the Spring Boot app
ENTRYPOINT ["java", "-jar", "app.jar"]