const express = require("express");
const cors = require("cors");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const PORT = process.env.PORT || 3000;
const { Pool } = require("pg");
const { DATABASE_URL } = import.meta.env.DATABASE_URL
const { SECRET_KEY } = import.meta.env.SECRET_KEY

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        require: true,
    },
});

app.use(cors());
app.use(express.json());

app.post("/signup", async (req, res) => {
    const client = await pool.connect();

    try {
        const { username, password } = req.body;
        const userResult = await client.query(
            "SELECT * FROM users WHERE username = $1",
            [username],
        );
        const hashedPassword = await bcrypt.hash(password, 12);
        if (userResult.rows.length > 0) {
            return res.status(400).json({ message: "Username already taken." });
        }
        await client.query(
            "INSERT INTO users (username, password) VALUES ($1,$2)",
            [username, hashedPassword],
        );
        console.log("New user registered.");
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Error", err.message);
        res.status(500).send({ error: err.message });
    } finally {
        client.release();
    }
});

app.post("/login", async (req, res) => {
    const client = await pool.connect();
    try {
        const userInfo = await client.query(
            "SELECT * FROM users WHERE username = $1",
            [req.body.username],
        );
        console.log("userResult", userInfo);
        const userData = userInfo.rows[0];
        console.log("userName", userData);

        if (!userData)
            return res.status(400).json({ message: "Username incorrect" });

        const passwordIsValid = await bcrypt.compare(
            req.body.password,
            userData.password,
        );
        if (!passwordIsValid) {
            return res.status(401).json({ auth: false, token: null });
        }
        var token = jwt.sign(
            { id: userData.id, username: userData.username },
            SECRET_KEY,
            {
                expiresIn: 86400,
            },
        );
        console.log("Logged in user with ID", userData.id);
        res.status(200).json({ auth: true, token: token });
    } catch (err) {
        console.error("Error", err.message);
        res.status(500).send({ error: err.message });
    } finally {
        client.release();
    }
});

app.post("/logout", async (req, res) => {
    res.status(200).json({ auth: false, token: null });

    app.get('/username', (req, res) => {
        const authToken = req.headers.authorization;
        if (!authToken) return res.status(401).json({ error: 'Access Denied.' });
        try {
            const verified = jwt.verify(authToken, SECRET_KEY);
            res.json({
                username: verified.username
            })
        } catch (err) {
            res.status(400).json({ error: "Invalid Token" })
        }
    });
});

app.get('/username', (req, res) => {
    const authToken = req.headers.authorization;
    if (!authToken) return res.status(401).json({ error: 'Access Denied.' });
    try {
        const verified = jwt.verify(authToken, SECRET_KEY);
        res.json({
            username: verified.username
        })
    } catch (err) {
        res.status(400).json({ error: "Invalid Token" })
    }
});

app.get("/posts/users/:user_id", async (req, res) => {
    const client = await pool.connect();
    const { user_id } = req.params;

    try {
        const posts = await client.query("SELECT * FROM posts WHERE user_id = $1", [
            user_id,
        ]);

        if (posts.rowCount > 0) {
            res.status(200).json(posts.rows);
        } else {
            res.status(400).json({ error: "No posts found from this user" });
        }
    } catch (err) {
        console.error("Error", err.message);
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});
// ----------------------------------------------------------------//
app.get("/likes", async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query("SELECT * FROM likes;");
        res.json(result.rows);
    } catch (err) {
        console.log(err.stack);
        res.status(500).send("An error occured");
    } finally {
        client.release();
    }
});

app.get("/likes/posts/:post_id", async (req, res) => {
    const client = await pool.connect();
    const { post_id } = req.params;
    try {
        const likes = await client.query(
            "SELECT users.username, users.id AS user_id, likes.id AS likes_id FROM likes INNER JOIN users ON likes.user_id = users.id WHERE likes.post_id = $1 AND active = true",
            [post_id],
        );
        res.json(likes.rows);
    } catch (err) {
        console.log(err.stack);
        res.status(500).send("An error occured");
    } finally {
        client.release();
    }
});

app.post("/posts", async (req, res) => {
    const { title, content, user_id } = req.body;
    const client = await pool.connect();
    try {
        const userExists = await client.query("SELECT id FROM users WHERE id=$1", [
            user_id,
        ]);
        console.log(userExists);
        if (userExists.rows.length > 0) {
            const post = await client.query(
                "INSERT INTO posts (title, content, user_id, created_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP) RETURNING *",
                [title, content, user_id],
            );
            res.json(post.rows[0]);
        } else {
            res.status(400).json({ error: "User does not exist" });
        }
    } catch (err) {
        console.error("Error", err.stack);
        res
            .status(500)
            .send({ error: "Something went wrong, please try again later!" });
    } finally {
        client.release();
    }
});

app.post("/likes", async (req, res) => {
    const { user_id, post_id } = req.body;
    const client = await pool.connect();
    try {
        const prevLike = await client.query(
            "SELECT * FROM likes WHERE user_id = $1 AND post_id = $2 AND active = false",
            [user_id, post_id],
        );
        if (prevLike.rowCount > 0) {
            const newLike = await client.query(
                "UPDATE likes SET active = true WHERE id = $1 RETURNING *",
                [prevLike.rows[0].id],
            );
            res.json(newLike.rows[0]);
        } else {
            const newLike = await client.query(
                "INSERT INTO likes (user_id, post_id, created_at) VALUES ($1, $2, CURRENT_TIMESTAMP) RETURNING *",
                [user_id, post_id],
            );
            res.json(newLike.rows[0]);
        }
    } catch (err) {
        console.log(err.stack);
        res.status(500).send("An error occured, please try again.");
    } finally {
        client.release();
    }
});

app.put("/likes/:userId/:postId", async (req, res) => {
    const { userId, postId } = req.params;
    const client = await pool.connect();
    try {
        await client.query(
            "UPDATE likes SET active = false WHERE user_id = $1 AND post_id = $2 AND active = true",
            [userId, postId],
        );
        res.json({ message: "The likes has been successfully removed!" });
    } catch (err) {
        console.error("Error", err.message);
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

app.delete("/likes", async (req, res) => {
    const { user_id, post_id } = req.body;
    const client = await pool.connect();
    try {
        await client.query(
            "DELETE FROM likes WHERE user_id = $1 AND post_id =$2;",
            [user_id, post_id],
        );
        res
            .status(200)
            .json({ message: "The like has been removed from the post." });
    } catch (err) {
        console.log(err.stack);
        res.status(500).send("An error occured, please try again.");
    } finally {
        client.release();
    }
});

app.get("/", (req, res) => {
    res.send("Welcome to the VExepress API!")
})

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})