import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const friendSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: SCHEMANAME.USER,
    },
    friendList: [
        { type: mongoose.Schema.Types.ObjectId, ref: SCHEMANAME.USER },
    ],
    count: {
        type: Number,
        default: 0,
    },
});

export default mongoose.model(SCHEMANAME.FRIEND, friendSchema);
