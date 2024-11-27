import express from "express";
import authController from "../api/entities/user/auth.controller";
import { registerLimiter } from "../core";
const authRoutes = express.Router();

authRoutes.post("/register", registerLimiter, authController.registerUser);

authRoutes.post("/login", authController.loginUser);

// authRoutes.post("/refresh", authController.requestAccessToken);

// authRoutes.post("/logout", authController.userLogout);

// authRoutes.get("/sendVerifyEmail/:id", authController.sendVerifyEmail);

// authRoutes.post("/forgotPassword", authController.forgotPasswordHandle);

export default authRoutes;
