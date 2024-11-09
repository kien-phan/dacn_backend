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
            unique: true,
            required: true,
        },
        password: {
            type: String,
            required: true,
            minLength: 6,
            maxLength: 16,
        },
        email: {
            type: String,
            minLength: 6,
            maxLength: 150,
            unique: true,
        },
        phone: {
            type: String,
            minLength: 6,
            maxLength: 150,
            unique: true,
        },
        avatar: {
            type: String,
            maxLength: 4096,
        },
        gender: {
            type: String,
            enum: ["male", "female", "unknown"],
            required: true,
        },
        biography: {
            type: String,
            maxLength: 4096,
        },
        score: {
            type: Number,
            default: 0,
        },
        channels: [{ type: String, maxLength: 100 }],
    },
    { timestamps: true }
);

export default mongoose.model(SCHEMANAME.USER, userSchema);
