import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const conversationSchema = new mongoose.Schema(
    {
        type: {
            type: String,
            required: true,
        },
        participants: [
            { type: mongoose.Schema.Types.ObjectId, ref: SCHEMANAME.USER },
        ],
        lastMessage: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.MESSAGE,
        },
        isBlock: {
            type: Boolean,
            default: false,
        },
    },
    { timestamps: true }
);

export default mongoose.model(SCHEMANAME.CONVERSATION, conversationSchema);
