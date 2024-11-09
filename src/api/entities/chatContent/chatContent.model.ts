import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const chatContentSchema = new mongoose.Schema(
    {
        chat_channel: {
            type: mongoose.Schema.Types.ObjectId,
            ref: SCHEMANAME.CHAT_CHANNEL,
        },
        messages: [
            {
                messageId: { type: mongoose.Schema.Types.ObjectId },
                content: {
                    type: String,
                },
                time: {
                    type: Date,
                    default: Date.now,
                },
                sender: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: SCHEMANAME.USER,
                },
            },
        ],
        order: {
            type: Number,
            required: true,
        },
        count: {
            type: Number,
            min: 0,
            max: 10,
        },
    },
    { timestamps: true }
);

export default mongoose.model(SCHEMANAME.CHAT_CONTENT, chatContentSchema);
