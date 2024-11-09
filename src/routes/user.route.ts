import express from "express";
const userRoutes = express.Router();

import { authMiddleware, upload } from "../../api/v1/middleware";
import userController from "../../api/v1/entities/user/user.controller";

//get all user
userRoutes.get(
    "/",
    authMiddleware.verifyTokenAndAdminAuth,
    userController.getAllUsers
);

//update 1 user
userRoutes.patch(
    "/update/:id",
    authMiddleware.verifyToken,
    authMiddleware.checkOwnAccount,
    userController.updateUser
);

userRoutes.patch(
    "/adminUpdateUser/:id",
    authMiddleware.verifyTokenAndAdminAuth,
    userController.adminUpdateUser
);

//delete 1 user
// userRoutes.delete('/delete/:id',  authMiddleware.verifyToken, userController.deleteUser)

userRoutes.post(
    "/uploadImagePortrait/:id",
    authMiddleware.verifyToken,
    authMiddleware.checkOwnAccount,
    upload.single("image"),
    userController.uploadImage
);

userRoutes.get(
    "/toggleActivateUser/:id",
    authMiddleware.verifyTokenAndAdminAuth,
    userController.toggleActivateUser
);

userRoutes.post(
    "/changePassword/:id",
    authMiddleware.verifyToken,
    authMiddleware.checkOwnAccount,
    userController.changePassword
);

//get 1 user by id
userRoutes.get("/:id", authMiddleware.verifyToken, userController.getOneUser);

export default userRoutes;
