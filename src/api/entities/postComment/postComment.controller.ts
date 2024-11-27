import { NextFunction, Request, Response } from "express";
import { postCommentCreateSchema } from "./postComment.validate";
import postCommentService from "./postComment.service";
import { STATUSCODE } from "../../../core";

const postCommentController = {
    createComment: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: CommentCreateDataInterface from body
            const validatedData = await postCommentCreateSchema().validateAsync(
                req.body
            );

            // create
            const comment = await postCommentService.createComment(
                validatedData
            );

            return res.status(STATUSCODE.OK).json(comment);
        } catch (error) {
            next(error);
        }
    },
    // get comment
    getComment: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: postId, optional: skip from query
            const postId = req.query.postId?.toString().trim();
            const skip = parseInt(req.query.page?.toString().trim() || "0");

            if (!postId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có postId từ query" });
            }

            // get
            const cmts = await postCommentService.getParentCmt(postId, skip);

            return res.status(STATUSCODE.OK).json(cmts);
        } catch (error) {
            next(error);
        }
    },

    // get children comment
    getChildren: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: parentId, optional: skip from query
            const parentId = req.query.parentId?.toString().trim();
            const skip = parseInt(req.query.page?.toString().trim() || "0");

            if (!parentId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có parentId từ query" });
            }

            // get
            const cmts = await postCommentService.getChildrenCmt(
                parentId,
                skip
            );

            return res.status(STATUSCODE.OK).json(cmts);
        } catch (error) {
            next(error);
        }
    },

    // delete
    deleteComment: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // require: cmtId from query
            const cmtId = req.query.cmtId?.toString().trim();

            if (!cmtId) {
                return res
                    .status(STATUSCODE.BAD)
                    .json({ msg: "Cần có cmtId từ query" });
            }

            // get
            const deletedCmt = await postCommentService.deleteCmt(cmtId);

            return res.status(STATUSCODE.OK).json(deletedCmt);
        } catch (error) {
            next(error);
        }
    },
    getAllPostComments: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            const PostComments = await postCommentService.getAllPostComments();

            return res.status(STATUSCODE.OK).json(PostComments);
        } catch (error) {
            next(error);
        }
    },
};

export default postCommentController;
