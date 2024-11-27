import Joi from "joi";

export const userCreateSchema = () => {
    return Joi.object({
        mobileNumberOrEmail: Joi.string().min(1).max(100).required(),
        password: Joi.string().min(6).max(16).required(),
        fullname: Joi.string().max(150).required(),
        username: Joi.string().min(1).max(100).required(),
    }).unknown(false);
};

export const userUpdateSchema = () => {
    return Joi.object({
        password: Joi.string().min(6).max(16).optional(),
        name: Joi.string().min(1).max(20).optional(),
    }).unknown(false);
};

export const userLogginSchema = () => {
    return Joi.object({
        mobileNumberOrEmailOrUsername: Joi.string().max(150).required(),
        password: Joi.string().min(6).required(),
    }).unknown(false);
};

export const changePasswordSchema = () => {
    return Joi.object({
        oldPassword: Joi.string().min(6).max(16).required(),
        newPassword: Joi.string().min(6).max(16).required(),
        confirmPassword: Joi.string().min(6).max(16).required(),
    }).unknown(false);
};

export const forgotPasswordSchema = () => {
    return Joi.object({
        email: Joi.string().min(6).max(150).required(),
        newPassword: Joi.string().min(6).max(16).required(),
        confirmPassword: Joi.string().min(6).max(16).required(),
    });
};
