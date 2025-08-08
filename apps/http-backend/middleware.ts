import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "./config";

interface CustomJwtPayload extends jwt.JwtPayload {
  userId: string;
  username: string;
}

declare module "express-serve-static-core" {
  interface Request {
    userId?: string;
  }
}

export default function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined");
  }

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res
      .status(401)
      .json({ message: "Invalid authorization header format" });
  }

  const token = parts[1] as string;

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as unknown;

    if (
      typeof decoded === "object" &&
      decoded !== null &&
      "userId" in decoded
    ) {
      req.userId = (decoded as CustomJwtPayload).userId;
      return next();
    }

    return res.status(401).json({ message: "Invalid token payload" });
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}
