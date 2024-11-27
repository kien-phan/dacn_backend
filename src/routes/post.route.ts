import express from "express";
import { authMiddleware } from "../api/middlewares/auth.middleware";
import postController from "../api/entities/post/post.controller";
import { uploadMultiple } from "../api/middlewares/multer";

const postRoutes = express.Router();

// get posts
postRoutes.post(
    "/getPosts",
    authMiddleware.verifyToken,
    postController.getPosts
);

// get one post
postRoutes.get(
    "/getOnePost",
    authMiddleware.verifyToken,
    postController.getOnePost
);

// get one post
postRoutes.get(
    "/getPostsOfOneUser",
    authMiddleware.verifyToken,
    postController.getPostsOfOneUser
);

// get post of one user
postRoutes.get(
    "/getPostsOfOneUser",
    authMiddleware.verifyToken,
    postController.getPostsOfOneUser
);

// create
postRoutes.post(
    "/create",
    uploadMultiple.any(),
    authMiddleware.verifyToken,
    postController.create
);

// update
postRoutes.post(
    "/update",
    authMiddleware.verifyToken,
    uploadMultiple.any(),
    postController.update
);

// delete
postRoutes.post(
    "/deleteOnePost",
    authMiddleware.verifyToken,
    postController.deleteOnePost
);

// like
postRoutes.post(
    "/likePost",
    authMiddleware.verifyToken,
    postController.likePost
);

// get all posts
postRoutes.get("/getAllPosts", postController.getAllPosts);

export default postRoutes;
