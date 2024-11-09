import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const chatChannelSchema = new mongoose.Schema(
    {
        participants: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: SCHEMANAME.USER,
            },
        ],
    },
    { timestamps: true }
);

export default mongoose.model(SCHEMANAME.CHAT_CHANNEL, chatChannelSchema);
