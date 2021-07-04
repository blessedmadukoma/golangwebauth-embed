CREATE DATABASE golangwebauth;

USE DATABASE golangwebauth;

CREATE TABLE user(
  id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
  firstname VARCHAR(255) NOT NULL,
  lastname VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  createdDate TIMESTAMP
);

-- Checking the content of the user table
DESCRIBE user;

-- Getting all the records in the user table
SELECT * FROM user;