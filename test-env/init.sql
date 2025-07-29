-- Database initialization for vulnerable test applications
CREATE DATABASE IF NOT EXISTS testdb;
USE testdb;

-- Create users table with test data
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test data
INSERT INTO users (username, password, name, email) VALUES
('admin', 'admin123', 'Administrator', 'admin@test.com'),
('user1', 'password123', 'John Doe', 'john@test.com'),
('user2', 'password456', 'Jane Smith', 'jane@test.com'),
('test', 'test123', 'Test User', 'test@test.com');

-- Create products table for additional testing
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(50)
);

-- Insert test products
INSERT INTO products (name, description, price, category) VALUES
('Test Product 1', 'This is a test product', 19.99, 'electronics'),
('Test Product 2', 'Another test product', 29.99, 'books'),
('Test Product 3', 'Yet another test product', 39.99, 'clothing');

-- Create comments table for XSS testing
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert test comments
INSERT INTO comments (user_id, comment) VALUES
(1, 'This is a test comment'),
(2, 'Another test comment'),
(3, 'Yet another test comment');

-- Grant permissions for test applications
GRANT ALL PRIVILEGES ON testdb.* TO 'testuser'@'%';
FLUSH PRIVILEGES; 