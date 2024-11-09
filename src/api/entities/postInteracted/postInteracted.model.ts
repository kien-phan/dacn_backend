import mongoose from "mongoose";
import { SCHEMANAME } from "../../../core";

const postInteractedSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: SCHEMANAME.USER,
    },
    post: { type: mongoose.Schema.Types.ObjectId, ref: SCHEMANAME.POST },
});

postInteractedSchema.index({ post: 1 });
export default mongoose.model(SCHEMANAME.POST_INTERACTED, postInteractedSchema);
