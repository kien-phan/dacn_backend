import bcrypt from "bcrypt";
import { NextFunction, Request, Response } from "express";

import userModel from "./user.model";
import userService from "./user.service";
import { MESSAGE, STATUSCODE } from "../../../core";
import { userCreateSchema, userLogginSchema } from "./user.validation";
import {
    generateAccessToken,
    isPhoneOrEmail,
} from "../../helpers/helpFunctions";

const authController = {
    //register as an admin
    registerUser: async (req: Request, res: Response, next: NextFunction) => {
        try {
            console.log(req.body);

            const [validatedData, salt] = await Promise.all([
                userCreateSchema().validateAsync(req.body),
                bcrypt.genSalt(10),
            ]);

            // check user exist
            const isUserExist = await userService.getUserByEmailPhoneUsername(
                validatedData.mobileNumberOrEmail
            );
            if (isUserExist) {
                return res.status(STATUSCODE.FORBIDDEN).json({
                    msg: "Lỗi khi đăng kí tài khoản: Email/Sdt/Username đã tồn tại",
                });
            }

            // encrypt password
            const hashedPassword = await bcrypt.hash(req.body.password, salt);
            const { mobileNumberOrEmail, ...userToCreate } = validatedData;
            userToCreate.password = hashedPassword;

            // check whether email or phone
            const check = isPhoneOrEmail(validatedData.mobileNumberOrEmail);
            if (check === "email") {
                userToCreate.email = mobileNumberOrEmail;
            } else if (check === "phone") {
                userToCreate.phone = mobileNumberOrEmail;
            } else {
                return res.status(STATUSCODE.BAD).json({
                    msg:
                        "Lỗi khi đăng kí tài khoản: " +
                        MESSAGE.WRONGACCOUNTFORMAT,
                });
            }

            // create
            const userCreated = await userService.createUser(userToCreate);
            if (!userCreated) {
                return res.status(STATUSCODE.SERVERERROR).json({
                    msg: "Lỗi khi đăng kí tài khoản: " + MESSAGE.UNKNOWNERROR,
                });
            }

            return res.status(STATUSCODE.OK).json({
                msg: "Register: OK",
            });
        } catch (error) {
            next(error);
        }
    },

    //login
    loginUser: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const validatedData = await userLogginSchema().validateAsync(
                req.body
            );

            console.log(validatedData, "validated data");
            console.log(req.body, "req body");

            //
            const user = await userModel.findOne({
                $or: [
                    { email: validatedData.mobileNumberOrEmailOrUsername },
                    { phone: validatedData.mobileNumberOrEmailOrUsername },
                    { username: validatedData.mobileNumberOrEmailOrUsername },
                ],
            });
            if (!user) {
                return res.status(404).json({ msg: "Account does not exist!" });
            }

            const validPassword = await bcrypt.compare(
                validatedData.password,
                user.password
            );
            if (!validPassword) {
                return res.status(404).json({ msg: "Wrong password" });
            }

            const accessToken = generateAccessToken(user);

            const { password, ...others } = user.toJSON();
            const responseData = {
                user: {
                    ...others,
                    accessToken,
                },
            };
            return res.status(STATUSCODE.OK).json(responseData);
        } catch (error) {
            return next(error);
        }
    },

    // forgotPasswordHandle: async (
    //     req: Request,
    //     res: Response,
    //     next: NextFunction
    // ) => {
    //     try {
    //         let otpCode = req.query.otpCode;
    //         const validatedData = await forgotPasswordSchema().validateAsync(
    //             req.body
    //         );
    //         const user = await userService.getUserByEmailPhoneUsername(
    //             validatedData.email
    //         );

    //         if (!user) {
    //             return res.status(STATUSCODE.BAD).json({
    //                 msg: `Lỗi khi đổi mật khẩu: Email ${validatedData.email} không tồn tại!`,
    //             });
    //         }

    //         if (!otpCode) {
    //             await sendOtpToUserEmail(
    //                 user.id,
    //                 user.email,
    //                 user.name || "undefined name"
    //             );
    //             return res.status(STATUSCODE.UNAUTH).json({
    //                 id: user.id,
    //                 msg: `Otp needed`,
    //             });
    //         } else {
    //             otpCode = otpCode.toString().trim();
    //             const code =
    //                 await VerificationCodeService.getVerificationCodeByUserId(
    //                     user.id
    //                 ).catch((err) => {
    //                     return res.status(404).json({
    //                         msg: "Lỗi khi đổi mật khẩu: otp Code đã hết hạn",
    //                     });
    //                 });
    //             if (code !== otpCode) {
    //                 return res.status(404).json({
    //                     msg: "Lỗi khi đổi mật khẩu: Otp Code không hợp lệ",
    //                 });
    //             }
    //         }

    //         if (validatedData.newPassword !== validatedData.confirmPassword) {
    //             return res.status(STATUSCODE.BAD).json({
    //                 msg: "Lỗi khi đổi mật khẩu: Mật khẩu xác nhận không khớp!",
    //             });
    //         }

    //         const salt = await bcrypt.genSalt(10);
    //         const hashed = await bcrypt.hash(validatedData.newPassword, salt);

    //         await userService.updateUser(user.id, { password: hashed });
    //         await VerificationCodeService.deleteCodeByUserId(user.id).catch(
    //             () => {}
    //         );

    //         return res.status(STATUSCODE.OK).json({ msg: "ok" });
    //     } catch (error) {
    //         next(error);
    //     }
    // },
};

export default authController;
