import { NextFunction, Request, Response } from "express";
import { CreatePostSchema, GetPostsSchema } from "./post.validate";
import postService from "./post.service";
import { STATUSCODE } from "../../../core";

const postController = {
    getPosts: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: userId from query, viewed posts in body
            const userId = req.query.userId?.toString().trim();
            const validatedData = req.body
                ? await GetPostsSchema().validateAsync(req.body)
                : [];

            if (!userId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có userId từ query" });
            }
            const posts = await postService.listPostsAdvance(
                userId,
                validatedData.viewedPosts
            );

            return res.status(STATUSCODE.OK).json(posts);
        } catch (error) {
            next(error);
        }
    },
    getOnePost: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: postId from query
            const postId = req.query.postId?.toString().trim();
            if (!postId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có postId từ query" });
            }

            // get
            const post = await postService.getOnePostById(postId);

            return res.status(STATUSCODE.OK).json(post);
        } catch (error) {
            next(error);
        }
    },
    getPostsOfOneUser: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            // require: userId from query
            const userId = req.query.userId?.toString().trim();
            if (!userId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có userId từ query" });
            }

            // get
            const posts = await postService.getPostOfOneUser(userId);

            return res.status(STATUSCODE.OK).json(posts);
        } catch (error) {
            next(error);
        }
    },
    create: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: PostCreateInterface from body
            // validate
            const validatedData = await CreatePostSchema().validateAsync(
                req.body
            );

            // upload file
            const files = Array.isArray(req.files) ? req.files : undefined;

            if (!files)
                return res
                    .status(STATUSCODE.BAD)
                    .json("Lỗi khi upload ảnh bài viết: lỗi files");

            const medias = await postService.uploadPostFiles(files);

            // create post
            const post = await postService.createOnePost({
                ...validatedData,
                medias,
            });

            return res.status(STATUSCODE.OK).json(post);
        } catch (error) {
            next(error);
        }
    },
    update: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: PostCreateInterface from body, postId from query
            const postId = req.query.postId?.toString().trim();
            if (!postId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có postId từ query" });
            }

            // validate
            const validatedData = await CreatePostSchema().validateAsync(
                req.body
            );

            // upload file
            const files = Array.isArray(req.files) ? req.files : undefined;

            if (!files)
                return res
                    .status(STATUSCODE.BAD)
                    .json("Lỗi khi upload ảnh bài viết: lỗi files");

            const medias = await postService.uploadPostFiles(files);

            // create post
            const post = await postService.updateOnePost(postId, {
                ...validatedData,
                medias,
            });

            return res.status(STATUSCODE.OK).json(post);
        } catch (error) {
            next(error);
        }
    },
    deleteOnePost: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: postId
            const postId = req.query.postId?.toString().trim();
            if (!postId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có postId từ query" });
            }

            // delete
            const post = await postService.deleteOnePost(postId);
            return res.status(STATUSCODE.OK).json(post);
        } catch (error) {
            next(error);
        }
    },
    likePost: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: userId, postId from query
            const postId = req.query.postId?.toString().trim();
            const userId = req.query.userId?.toString().trim();
            if (!postId || !userId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có postId & userId từ query" });
            }
            await postService.likePost(userId, postId);

            return res.status(STATUSCODE.OK).json({ msg: "ok" });
        } catch (error) {
            next(error);
        }
    },
    getAllPosts: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const Posts = await postService.getAllPosts();

            return res.status(STATUSCODE.OK).json(Posts);
        } catch (error) {
            next(error);
        }
    },
};

export default postController;
