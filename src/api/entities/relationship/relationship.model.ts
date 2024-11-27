import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const relationshipSchema = new mongoose.Schema({
    user1: {
        type: mongoose.Schema.Types.ObjectId,
        ref: SCHEMANAME.USER,
        required: true,
    }, // not unique
    user2: {
        type: mongoose.Schema.Types.ObjectId,
        ref: SCHEMANAME.USER,
        required: true,
    }, // not unique
    relationship: {
        type: String,
        enum: ["friend", "following"],
        required: true,
    },
});

export default mongoose.model(SCHEMANAME.FRIEND, relationshipSchema);
