const express = require('express');
const bodyParser = require('body-parser');
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Load environment variables from .env file
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 4001;

// PostgreSQL connection configuration
const client = new Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432, // Default PostgreSQL port
    ssl: {
        rejectUnauthorized: false, // Set to false if using self-signed certificates
        // You may need to provide other SSL options such as ca, cert, and key
        // Example:
        // ca: fs.readFileSync('path/to/ca-certificate.crt'),
        // cert: fs.readFileSync('path/to/client-certificate.crt'),
        // key: fs.readFileSync('path/to/client-certificate.key')
    },
});

// Middleware for parsing JSON bodies
app.use(bodyParser.json());
app.use(cors());

// Connect to PostgreSQL database
client.connect()
    .then(() => console.log('Connected to PostgreSQL'))
    .catch(error => console.error('Error connecting to PostgreSQL:', error));

// Helper function to hash passwords
const hashPassword = async (password) => {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
};

// Helper function to compare passwords
const comparePasswords = async (plainPassword, hashedPassword) => {
    return bcrypt.compare(plainPassword, hashedPassword);
};

// Helper function to generate JWT token
const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, error: 'Unauthorized: Invalid token' });
        }
        req.userId = decoded.userId;
        next();
    });
};

// Create users table if not exists
const createUsersTable = async () => {
    try {
        // Define the SQL query to create the users table
        const query = `
            CREATE TABLE IF NOT EXISTS blog_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(100) NOT NULL
            )
        `;
        // Execute the query
        await client.query(query);
        console.log('blog_users table created successfully');
    } catch (error) {
        console.error('Error creating blog_users table:', error);
    }
};

// Call the function to create users table
createUsersTable();

// POST endpoint for user signup
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if the username or email already exists
        const userExistsQuery = 'SELECT * FROM blog_users WHERE username = $1 OR email = $2';
        const userExistsResult = await client.query(userExistsQuery, [username, email]);
        if (userExistsResult.rows.length > 0) {
            return res.status(400).json({ success: false, error: 'Username or email already exists' });
        }

        // Insert the new user into the users table
        const createUserQuery = 'INSERT INTO blog_users (username, email, password) VALUES ($1, $2, $3) RETURNING *';
        const hashedPassword = await hashPassword(password);
        const createUserResult = await client.query(createUserQuery, [username, email, hashedPassword]);

        const newUser = createUserResult.rows[0];
        // const token = generateToken(newUser.id);
        res.status(201).json({ success: true, user: newUser });
    } catch (error) {
        console.error('Error signing up:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});


// POST endpoint for user authentication (login)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if the username or email exists
        const getUserQuery = 'SELECT * FROM blog_users WHERE  email = $1';
        const getUserResult = await client.query(getUserQuery,[email] );
        const user = getUserResult.rows[0];
        console.log(user);
        
        if (!user) {
            return res.status(401).json({ success: false, error: 'Invalid username or email or password' });
        }

        // Compare the provided password with the hashed password stored in the database
        const passwordMatch = await comparePasswords(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, error: 'Invalid username or email or password' });
        }

        // Generate JWT token and return it along with user information
        const token = generateToken(user.id);
        res.status(200).json({ success: true, user, token });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});

const createPostsTable = async () => {
    try {
        // Define the SQL query to create the posts table
        const query = `
            CREATE TABLE IF NOT EXISTS posts (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL,
                author VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        // Execute the query
        await client.query(query);
        console.log('Posts table created successfully');
    } catch (error) {
        console.error('Error creating posts table:', error);
    }
};

// POST endpoint for creating a new blog post
app.post('/api/posts', async (req, res) => {
    try {
        const { title, content, author } = req.body;

        // Insert the new post into the posts table
        const insertQuery = 'INSERT INTO posts (title, content, author) VALUES ($1, $2, $3) RETURNING *';
        const insertResult = await client.query(insertQuery, [title, content, author]);

        const newPost = insertResult.rows[0];
        res.status(201).json({ success: true, post: newPost });
    } catch (error) {
        console.error('Error posting blog:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
