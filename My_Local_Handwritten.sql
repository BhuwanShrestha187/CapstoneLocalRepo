CREATE DATABASE HandwritingRecognitionDB;
GO

USE HandwritingRecognitionDB;
GO

CREATE TABLE Users (
    id INT IDENTITY(1,1) PRIMARY KEY,
	email NVARCHAR(100) UNIQUE NOT NULL,
    username NVARCHAR(50) UNIQUE NOT NULL,
    password_hash VARBINARY(256) NULL,
	google_id VARCHAR(50) NULL, 
	is_google_user BIT NOT NULL DEFAULT 0
);
GO

-- Insert a test user (Password: 'test123' hashed using SHA2_256)
INSERT INTO Users (username, email, password_hash, is_google_user)
VALUES ('Admin', 'admin@gmail.com', 0x243262243132244b58385838583858385838583858385838583858385838583858385838583858385838583858385838583858385838583858, 0);
GO



--List all the users
SELECT * FROM Users;

SELECT username, email, password_hash FROM Users;

DROP TABLE Users; 
SELECT password_hash FROM Users WHERE email = 'admin@gmail.com';



