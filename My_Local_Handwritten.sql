CREATE DATABASE HandwritingRecognitionDB;
GO

USE HandwritingRecognitionDB;
GO

CREATE TABLE Users (
    id INT IDENTITY(1,1) PRIMARY KEY,
	email NVARCHAR(100) UNIQUE NOT NULL,
    username NVARCHAR(50) UNIQUE NOT NULL,
    password_hash VARBINARY(32) NOT NULL
);
GO

-- Insert a test user (Password: 'test123' hashed using SHA2_256)
INSERT INTO Users (username, email, password_hash)
VALUES ('Admin', 'admin@gmail.com', HASHBYTES('SHA2_256', 'password'));
GO

--List all the users
SELECT * FROM Users;
ALTER TABLE Users 
ALTER COLUMN password_hash VARBINARY(32);
SELECT username, email, password_hash FROM Users;

DROP TABLE Users; 
