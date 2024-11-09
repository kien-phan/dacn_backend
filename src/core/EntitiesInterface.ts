import mongoose, { Document } from "mongoose";

// USER
export interface UserCreateInterface {
    password: string;
    fullname: string;
    username: string;
    phone?: string;
    email?: string;
}

export interface UserUpdateInterface {
    name?: string;
    password?: string;
}

export interface UserDocument extends Document {
    fullname: string;
    username: string;
    password: string;
    email: string;
    phone: string;
    avatar: string;
    gender: string;
    biography: string;
    score: number;
    channels: string[];

    createdAt?: Date;
    updatedAt?: Date;
}
