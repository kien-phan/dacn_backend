import mongoose from "mongoose";
import jwt from "jsonwebtoken";

import { UserDocument, UserJwtInterface } from "../../core";

export function isPhoneOrEmail(input: string) {
    // Biểu thức chính quy để kiểm tra email
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    // Biểu thức chính quy để kiểm tra số điện thoại (chỉ gồm số, có độ dài từ 10 đến 15)
    const phoneRegex = /^\d{10,15}$/;

    if (emailRegex.test(input)) {
        return "email";
    } else if (phoneRegex.test(input)) {
        return "phone";
    } else {
        return "invalid";
    }
}

export function generateAccessToken(
    user: UserDocument & {
        _id: mongoose.Types.ObjectId;
    }
) {
    // console.log('[generateAccessToken]', user);
    try {
        return jwt.sign(
            {
                id: user.id,
                email: user.email || null,
                phone: user.phone || null,
                username: user.username || null,
            },
            process.env.JWT_KEY as string,
            {
                expiresIn: "1d",
            }
        );
    } catch (error: any) {
        throw new Error(`Lỗi khi tạo AccessToken ${error.message}`);
    }
}

export function generateRefreshToken(
    user: UserDocument & {
        _id: mongoose.Types.ObjectId;
    }
) {
    try {
        return jwt.sign(
            {
                id: user.id,
                email: user.email || null,
                phone: user.phone || null,
                username: user.username || null,
            },
            process.env.JWT_KEY as string,
            {
                expiresIn: "7d",
            }
        );
    } catch (error: any) {
        throw new Error(`generateRefreshToken ${error.message}`);
    }
}
