import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const postCommentSchema = new mongoose.Schema(
    {
        post: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.POST,
            index: true,
        },
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.USER,
        },
        parent: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.POST_COMMENT,
            index: true,
            default: null,
        },
        content: {
            type: String,
            required: true,
            trim: true,
            minlength: 1,
            maxlength: 500,
        },
        childrenNum: {
            type: Number,
            default: 0,
            min: 0,
        },
        replyTo: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.USER,
            default: null,
        },
    },
    { timestamps: true }
);

export default mongoose.model(SCHEMANAME.POST_COMMENT, postCommentSchema);
