import express from "express";
import { authMiddleware } from "../api/middlewares/auth.middleware";
import messageController from "../api/entities/message/message.controller";
import { uploadMultiple } from "../api/middlewares/multer";

const messageRoutes = express.Router();

messageRoutes.get(
    "/getMessage",
    authMiddleware.verifyToken,
    messageController.getMessage
);

messageRoutes.post(
    "/sendMessage",
    uploadMultiple.any(),
    authMiddleware.verifyToken,
    messageController.sendMessage
);

messageRoutes.get(
    "/readMessage",
    authMiddleware.verifyToken,
    messageController.readMessage
);

messageRoutes.get(
    "/deleteMessage",
    authMiddleware.verifyToken,
    messageController.deleteMessage
);

export default messageRoutes;
