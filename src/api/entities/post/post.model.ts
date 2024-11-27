import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";
import { min } from "moment-timezone";

const postSchema = new mongoose.Schema(
    {
        author: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.USER,
        },
        title: {
            type: String,
            required: true,
            minLength: 1,
            maxLength: 500,
        },
        location: {
            type: String,
        },
        collaborators: [
            { type: mongoose.Schema.Types.ObjectId, ref: SCHEMANAME.POST },
        ],
        medias: [
            {
                type: {
                    type: String,
                    enum: ["image", "video"],
                },
                source: {
                    type: String,
                    maxLength: 500,
                },
            },
        ],
        likeNum: {
            type: Number,
            default: 0,
            min: 0,
        },
        commentNum: {
            type: Number,
            default: 0,
            min: 0,
        },
        isCommentAble: {
            type: Boolean,
            default: true,
        },
        isShowLike: {
            type: Boolean,
            default: true,
        },
        score: {
            type: Number,
            default: 0,
        },
        hashtags: [{ type: String }],
    },
    { timestamps: true }
);

postSchema.index({ author: 1, createdAt: -1 });

export default mongoose.model(SCHEMANAME.POST, postSchema);
