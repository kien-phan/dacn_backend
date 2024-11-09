import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { NextFunction, Request, Response } from "express";

import userModel from "./user.model";
import userService from "./user.service";
import mongoose from "mongoose";
import { MESSAGE, STATUSCODE, UserJwtInterface } from "../../../../core";
import {
    forgotPasswordSchema,
    userCreateSchema,
    userLogginSchema,
} from "./user.validation";

const authController = {
    //register as an admin
    registerUser: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const [validatedData, salt] = await Promise.all([
                userCreateSchema().validateAsync(req.body),
                bcrypt.genSalt(10),
            ]);

            // check captcha
            // const captchaResult = await fetch(
            //     `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.G_RECAPTCHA_V2_SECRET_KEY}&response=${validatedData.captchaToken}`,
            //     {
            //         method: "POST",
            //         headers: {
            //             "Content-Type": "application/json",
            //         },
            //     }
            // );

            // if (!captchaResult.ok) {
            //     return res.status(STATUSCODE.BAD).json({
            //         msg: "Captcha failed",
            //     });
            // }
            // const captchaResultData = await captchaResult.json();
            // if (!captchaResultData.success) {
            //     return res.status(STATUSCODE.BAD).json({
            //         msg: "Captcha failed",
            //     });
            // }

            //
            const isUserExist = await userService.getUserByEmail(
                validatedData.email
            );
            if (isUserExist) {
                return res.status(STATUSCODE.FORBIDDEN).json({
                    msg: "Lỗi khi đăng kí tài khoản: Tài khoản này đã tồn tại",
                });
            }

            const hashedPassword = await bcrypt.hash(req.body.password, salt);
            const { confirmPassword, ...userToCreate } = validatedData;
            userToCreate.password = hashedPassword;
            const userCreated = await userService.createUser(userToCreate);
            if (!userCreated) {
                return res.status(STATUSCODE.SERVERERROR).json({
                    msg: "Lỗi khi đăng kí tài khoản: " + MESSAGE.UNKNOWNERROR,
                });
            }

            const verificationCode = crypto.randomBytes(16).toString("hex");
            await VerificationCodeService.saveCode({
                code: verificationCode,
                user: userCreated.id,
            });

            const verifyEmailTemplate = emailHtmlTemplate.verifyEmailTemplate(
                "" + userCreated.id + userCreated.name,
                `${process.env.SERVICE_BASE_URL}/api/v1/others/verify/email/${userCreated.id}/${verificationCode}`
            );
            othersHelper.sendEmail(
                userCreated.email,
                "[TSGiaYen] Xác minh tài khoản",
                verifyEmailTemplate
            );
            return res.status(STATUSCODE.OK).json({
                msg: "Tài khoản đã được tạo. Vui lòng kiểm tra email để xác minh.",
            });
        } catch (error) {
            next(error);
        }
    },

    //login. just access and refresh token
    loginUser: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const validatedData = await userLogginSchema().validateAsync(
                req.body
            );

            // check captcha
            const captchaResult = await fetch(
                `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.G_RECAPTCHA_V3_SECRET_KEY}&response=${validatedData.captchaToken}`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                }
            );

            if (!captchaResult.ok) {
                return res.status(STATUSCODE.BAD).json({
                    msg: "Captcha failed",
                });
            }
            const captchaResultData = await captchaResult.json();
            if (
                !captchaResultData.success ||
                captchaResultData.score < 0.5 ||
                captchaResultData.action !== "login"
            ) {
                return res.status(STATUSCODE.BAD).json({
                    msg: "Captcha failed",
                });
            }

            //
            const user = await userModel.findOne({
                email: validatedData.email,
            });
            if (!user) {
                return res.status(404).json({ msg: "Wrong email" });
            }

            const validPassword = await bcrypt.compare(
                validatedData.password,
                user.password
            );
            if (!validPassword) {
                return res.status(404).json({ msg: "Wrong password" });
            }

            if (!user.isActive) {
                return res.status(418).json({
                    id: user.id,
                    msg: `Tài khoản của bạn đã bị khóa!`,
                });
            }

            if (!user.isVerified) {
                return res.status(STATUSCODE.FORBIDDEN).json({
                    id: user.id,
                    msg: `Tài khoản của bạn chưa được xác minh! Vui lòng kiểm tra email ${user.email}!`,
                });
            }

            let refreshTokenGenerated;
            const UserRFTokenExist =
                await refreshTokenService.getRefreshTokenByUserId(user.id);
            if (!UserRFTokenExist) {
                //truong hop dang nhap lan dau
                await sendOtpToUserEmail(
                    user.id,
                    user.email,
                    user.name || "undefined name"
                );
                return res.status(STATUSCODE.UNAUTH).json({
                    id: user.id,
                    msg: `Nhập mã OTP được gửi đến email: ${user.email}!`,
                });
            }

            refreshTokenGenerated = UserRFTokenExist.refreshToken;

            const accessToken = authController.generateAccessToken(user);

            const { password, ...others } = user.toJSON();
            const responseData = {
                user: {
                    ...others,
                    accessToken,
                    refreshToken: refreshTokenGenerated,
                },
            };
            return res.status(STATUSCODE.OK).json(responseData);
        } catch (error) {
            next(error);
        }
    },

    userLogout: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const refreshToken = req.headers.refreshToken?.toString().trim();
            if (refreshToken) {
                await refreshTokenService.deleteByToken(refreshToken);
            } else {
                const userid = req.headers.userid?.toString().trim();
                if (userid) await refreshTokenService.deleteByUserId(userid);
            }

            return res.status(STATUSCODE.OK).json("Logged out!");
        } catch (error) {
            return next(error);
        }
    },

    forgotPasswordHandle: async (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        try {
            let otpCode = req.query.otpCode;
            const validatedData = await forgotPasswordSchema().validateAsync(
                req.body
            );
            const user = await userService.getUserByEmail(validatedData.email);

            if (!user) {
                return res.status(STATUSCODE.BAD).json({
                    msg: `Lỗi khi đổi mật khẩu: Email ${validatedData.email} không tồn tại!`,
                });
            }

            if (!otpCode) {
                await sendOtpToUserEmail(
                    user.id,
                    user.email,
                    user.name || "undefined name"
                );
                return res.status(STATUSCODE.UNAUTH).json({
                    id: user.id,
                    msg: `Otp needed`,
                });
            } else {
                otpCode = otpCode.toString().trim();
                const code =
                    await VerificationCodeService.getVerificationCodeByUserId(
                        user.id
                    ).catch((err) => {
                        return res.status(404).json({
                            msg: "Lỗi khi đổi mật khẩu: otp Code đã hết hạn",
                        });
                    });
                if (code !== otpCode) {
                    return res.status(404).json({
                        msg: "Lỗi khi đổi mật khẩu: Otp Code không hợp lệ",
                    });
                }
            }

            if (validatedData.newPassword !== validatedData.confirmPassword) {
                return res.status(STATUSCODE.BAD).json({
                    msg: "Lỗi khi đổi mật khẩu: Mật khẩu xác nhận không khớp!",
                });
            }

            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(validatedData.newPassword, salt);

            await userService.updateUser(user.id, { password: hashed });
            await VerificationCodeService.deleteCodeByUserId(user.id).catch(
                () => {}
            );

            return res.status(STATUSCODE.OK).json({ msg: "ok" });
        } catch (error) {
            next(error);
        }
    },
};

export default authController;
