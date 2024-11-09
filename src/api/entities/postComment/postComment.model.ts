import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const postCommentSchema = new mongoose.Schema(
    {
        post: { type: mongoose.Schema.Types.ObjectId, ref: SCHEMANAME.POST },
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.USER,
        },
        parent: { type: String, maxLength: 100 },
        content: { type: String, required: true },
        replyNum: {
            type: Number,
            default: 0,
        },
    },
    { timestamps: true }
);

export default mongoose.model(SCHEMANAME.POST_COMMENT, postCommentSchema);
