import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const messageSchema = new mongoose.Schema(
    {
        conversation: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.CONVERSATION,
            required: true,
        },
        sender: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.USER,
            required: true,
        },
        forwardFrom: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.MESSAGE,
        },
        medias: [
            {
                type: {
                    type: String,
                    required: true,
                },
                source: {
                    type: String,
                    required: true,
                },
                fileName: {
                    type: String,
                },
            },
        ],
        content: {
            type: String,
        },
        isRead: {
            type: Boolean,
            default: false,
        },
    },
    { timestamps: true }
);
messageSchema.index({ conversationId: 1, createdAt: -1 });
export default mongoose.model(SCHEMANAME.MESSAGE, messageSchema);
