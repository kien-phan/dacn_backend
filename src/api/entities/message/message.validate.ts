import Joi from "joi";

export const SendMessageSchema = () => {
    return Joi.object({
        conversation: Joi.string().min(1).max(100).required(),
        sender: Joi.string().min(1).max(100).required(),
        forwardFrom: Joi.string()
            .min(1)
            .max(100)
            .allow("")
            .allow(null)
            .optional(),
        content: Joi.string().allow("").allow(null).optional(),
    }).unknown(true);
};
