import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const userSaveSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: SCHEMANAME.USER,
    },
    post: [{ type: mongoose.Schema.Types.ObjectId, ref: SCHEMANAME.POST }],
});

export default mongoose.model(SCHEMANAME.USER_SAVE, userSaveSchema);
