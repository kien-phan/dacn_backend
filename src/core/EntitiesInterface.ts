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
    fullname?: string | null;
    username?: string | null;
    password: string;
    email?: string | null;
    phone?: string | null;
    avatar?: string | null;
    biography?: string | null;
    score: number;
    channels: string[];
    createdAt?: Date;
    updatedAt?: Date;
}

// POST
export interface PostCreateInterface {
    author: string | mongoose.Types.ObjectId;
    title: string;
    location: string;
    collaborators: string[] | mongoose.Types.ObjectId[];
    medias: {
        type: string;
        source: string;
    }[];
    isCommentAble?: Boolean;
    isShowLike?: Boolean;
    hashtags: string[];
}

// COMMENT
export interface CommentCreateDataInterface {
    post: string | mongoose.Types.ObjectId;
    user: string | mongoose.Types.ObjectId;
    parent?: string | mongoose.Types.ObjectId;
    content: string;
    replyTo?: string | mongoose.Types.ObjectId;
}

export interface MessageCreateInterface {
    conversation: string | mongoose.Types.ObjectId;
    sender: string | mongoose.Types.ObjectId;
    forwardFrom?: string | mongoose.Types.ObjectId;
    medias?:
        | {
              type: string;
              source: string;
              fileName: string;
          }[]
        | null;
    content?: string | null;
}
