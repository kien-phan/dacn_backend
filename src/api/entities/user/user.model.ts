import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const userSchema = new mongoose.Schema(
    {
        fullname: {
            type: String,
            minLength: 1,
            maxLength: 20,
        },
        username: {
            type: String,
            minLength: 1,
            maxLength: 20,
        },
        password: {
            type: String,
            required: true,
            minLength: 6,
        },
        email: {
            type: String,
            minLength: 6,
            maxLength: 150,
        },
        phone: {
            type: String,
            minLength: 6,
            maxLength: 150,
        },
        avatar: {
            type: String,
            maxLength: 4096,
        },
        biography: {
            type: String,
            maxLength: 4096,
        },
        score: {
            type: Number,
            default: 0,
        },
        isOnline: {
            type: Boolean,
            default: false,
        },
        channels: [{ type: String, maxLength: 100 }],
    },
    { timestamps: true }
);

userSchema.index({ fullname: "text", username: "text" });

export default mongoose.model(SCHEMANAME.USER, userSchema);
