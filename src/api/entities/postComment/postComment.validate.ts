import Joi from "joi";

export const postCommentCreateSchema = () => {
    return Joi.object({
        post: Joi.string().min(1).max(100).required(),
        user: Joi.string().min(1).max(100).required(),
        parent: Joi.string().max(100).allow("").allow(null).optional(),
        content: Joi.string().min(1).required(),
        replyTo: Joi.string().max(100).allow("").allow(null).optional(),
    }).unknown(false);
};
