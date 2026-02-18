CREATE DATABASE smart_library11;

USE smart_library11;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(100),
    user_email VARCHAR(150) UNIQUE
);
SHOW TABLES;
DESCRIBE users;
SELECT * FROM users;

