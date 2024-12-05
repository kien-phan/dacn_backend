import Joi from "joi";

export const CreateConversationSchema = () => {
    return Joi.object({
        type: Joi.string().min(1).required(),
        participants: Joi.array().items(Joi.string()).required(),
    }).unknown(true);
};
