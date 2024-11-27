import Joi from "joi";

export const GetPostsSchema = () => {
    return Joi.object({
        viewedPosts: Joi.array()
            .items(Joi.string())
            .allow(null)
            .allow("")
            .optional(),
    }).unknown(false);
};

export const CreatePostSchema = () => {
    return Joi.object({
        author: Joi.string().min(1).max(100).required(),
        title: Joi.string().min(1).required(),
        location: Joi.string().allow("").allow(null).optional(),
        collaborators: Joi.array()
            .items(Joi.string())
            .allow("")
            .allow(null)
            .optional(),
        isCommentAble: Joi.boolean().optional(),
        isShowLike: Joi.boolean().optional(),
        hashtags: Joi.array()
            .items(Joi.string())
            .allow("")
            .allow(null)
            .optional(),
    }).unknown(true);
};
