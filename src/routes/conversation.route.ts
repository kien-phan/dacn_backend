import express from "express";
import { authMiddleware } from "../api/middlewares/auth.middleware";
import conversationController from "../api/entities/conversation/conversation.controller";

const conversationRoutes = express.Router();

conversationRoutes.get(
    "/getConversationOfOneUser",
    authMiddleware.verifyToken,
    conversationController.getConversationOfOneUser
);

conversationRoutes.post(
    "/create",
    authMiddleware.verifyToken,
    conversationController.createConversation
);

conversationRoutes.get(
    "/delete",
    authMiddleware.verifyToken,
    conversationController.deleteConversation
);

export default conversationRoutes;
