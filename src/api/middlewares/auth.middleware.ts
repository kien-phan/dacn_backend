import jwt from "jsonwebtoken";

import userService from "../entities/user/user.service";
import { NextFunction, Request, Response } from "express";
import { MESSAGE, STATUSCODE, UserJwtInterface } from "../../../core";

export const authMiddleware = {
    verifyToken: async (req: Request, res: Response, next: NextFunction) => {
        const token = req.headers.token as string;
        if (token) {
            const accessToken = token.split(" ")[1]; //"Bearer 5da56d6aa"

            jwt.verify(
                accessToken,
                process.env.JWT_KEY as string,
                async (err: any, user: any) => {
                    if (err) {
                        return res.status(STATUSCODE.UNAUTH).json({
                            msg: MESSAGE.TOKENEXPIRE,
                        });
                    }
                    req.user = user as UserJwtInterface;

                    const userFromDb = await userService.getUserById(
                        req.user.id
                    );
                    if (!userFromDb?.isActive) {
                        return res
                            .status(STATUSCODE.FORBIDDEN)
                            .json({ msg: MESSAGE.ACCOUNTBLOCK });
                    }
                    next();
                }
            );
        } else {
            return res
                .status(STATUSCODE.UNAUTH)
                .json({ msg: MESSAGE.LOGINREQUIRE });
        }
    },
    verifyTokenAndAdminAuth: (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        authMiddleware.verifyToken(req, res, () => {
            if (req.user && req.user.isAdmin) {
                next();
            } else {
                res.status(STATUSCODE.UNAUTH).json({
                    msg: MESSAGE.NOPERMISSION,
                });
            }
        });
    },
    // phải đặt middleware này sau verifyToken
    checkOwnAccount: (req: Request, res: Response, next: NextFunction) => {
        if (req.user && req.params.id.toString().trim() !== req.user.id) {
            return res
                .status(STATUSCODE.FORBIDDEN)
                .json({ msg: MESSAGE.NOPERMISSION });
        } else {
            next();
        }
    },
    checkOwnAccountAcceptAdmin: (
        req: Request,
        res: Response,
        next: NextFunction
    ) => {
        if (
            req.user &&
            req.params.id.toString().trim() !== req.user.id &&
            !req.user.isAdmin
        ) {
            return res
                .status(STATUSCODE.FORBIDDEN)
                .json({ msg: MESSAGE.NOPERMISSION });
        } else {
            next();
        }
    },
};
