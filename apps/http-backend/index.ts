import express from "express";
import { prismaClient } from "db/client";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "./config";
import dotenv from "dotenv";
import authMiddleware from "./middleware";

dotenv.config();

const port = 3003;
const app = express();
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({
    message: "Server healthy",
  });
});

app.post("/api/signup", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const hashedPassword = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 5,
      parallelism: 1,
      hashLength: 32,
    });

    try {
      const user = await prismaClient.user.create({
        data: {
          username: username,
          password: hashedPassword,
        },
      });

      return res.status(200).json({
        message: "User created",
        user,
      });
    } catch (e) {
      console.error("Database error: ", e);
      return res.status(401).json({
        message: "Username already exists",
      });
    }
  } catch (e) {
    console.error("Hashing error: ", e);
    return res.status(401).json({
      message: "Error generating hash",
    });
  }
});

app.post("/api/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const user = await prismaClient.user.findUnique({
      where: {
        username: username,
      },
    });

    if (!user || !user.password) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const verifiedPass = await argon2.verify(user?.password, password);

    if (!verifiedPass) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET!
    );

    return res.status(200).json({
      message: "Logged in successfully",
      token,
    });
  } catch (e) {
    console.error("Login error: ", e);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.get("/api/mytodos", authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    if (!userId) {
      return res.status(401).json({ message: "User ID not found" });
    }

    const todos = await prismaClient.todo.findMany({
      where: {
        userId: userId,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.status(200).json({
      message: "Todos fetched successfully",
      todos,
    });
  } catch (e) {
    console.error("Error fetching todos: ", e);
    res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.post("/api/todos", authMiddleware, async (req, res) => {
  try {
    if (!req.userId) {
      return res.status(401).json({
        message: "User not found",
      });
    }

    const task = req.body.task;

    if (!task || typeof task !== "string") {
      return res.status(400).json({
        message: "Task is required and must be a string",
      });
    }

    const addTodo = await prismaClient.todo.create({
      data: {
        task: task,
        userId: req.userId,
      },
    });

    res.status(200).json({
      message: "Todo added successfully",
      todo: addTodo,
    });
  } catch (e) {
    console.error("Error creating todo: ", e);
    res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
