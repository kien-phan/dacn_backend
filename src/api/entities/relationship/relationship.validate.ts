import Joi from "joi";

export const relationshipCreateSchema = () => {
    return Joi.object({
        user1: Joi.string().min(1).max(100).required(),
        user2: Joi.string().min(6).max(100).required(),
        relationship: Joi.string().valid("friend", "following").required(),
    }).unknown(false);
};
