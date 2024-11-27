import express from "express";
const postCommentRoutes = express.Router();

import { authMiddleware } from "../api/middlewares/auth.middleware";
import postCommentController from "../api/entities/postComment/postComment.controller";

// get comment
postCommentRoutes.get(
    "/getComment",
    authMiddleware.verifyToken,
    postCommentController.getComment
);

// get children
postCommentRoutes.get(
    "/getChildren",
    authMiddleware.verifyToken,
    postCommentController.getChildren
);

// createComment
postCommentRoutes.post(
    "/createComment",
    authMiddleware.verifyToken,
    postCommentController.createComment
);

postCommentRoutes.post(
    "/deleteComment",
    authMiddleware.verifyToken,
    postCommentController.deleteComment
);

// get all postComments
postCommentRoutes.get(
    "/getAllComments",
    postCommentController.getAllPostComments
);

export default postCommentRoutes;
