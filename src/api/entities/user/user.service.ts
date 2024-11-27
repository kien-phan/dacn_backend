import userModel from "./user.model";
import { UserCreateInterface, UserUpdateInterface } from "../../../core";

const userService = {
    getAllUsers: async () => {
        return await userModel.find().lean();
    },
    getUserByEmailPhoneUsername: async (input: string) => {
        return await userModel.findOne({
            $or: [{ email: input }, { phone: input }, { username: input }],
        });
    },
    getUserById: async (id: string) => {
        return await userModel.findById(id);
    },
    createUser: async (userData: UserCreateInterface) => {
        const user = new userModel(userData);
        await user.save();
        return user;
    },
    updateUser: async (id: string, objectUpdate: UserUpdateInterface) => {
        const updatedUser = await userModel.findOneAndUpdate(
            { _id: id },
            objectUpdate,
            { new: true }
        );
        return updatedUser;
    },
    searchUser: async (input: string) => {
        const users = await userModel
            .find({
                $text: { $search: input },
            })
            .lean();
        return users;
    },

    // uploadImagePortrait: async (idUser: string, file: Express.Multer.File) => {
    //     const user = await userModel.findById(idUser);
    //     if (!user) {
    //         throw new Error("Lỗi khi upload avatar: Không tìm thấy user");
    //     }
    //     // Kiểm tra xem có tệp hình ảnh cũ không
    //     if (user.imagePortrait) {
    //         await firebaseImageActions
    //             .deleteImageFromFireBase(user.imagePortrait)
    //             .catch(() => {});
    //     }

    //     const downloadUrl = await firebaseImageActions.uploadImageToFirebase(
    //         file,
    //         "single",
    //         "userImages"
    //     );

    //     // Cập nhật trường `image_portrait` chỉ khi có sự thay đổi
    //     if (downloadUrl && user.imagePortrait !== downloadUrl) {
    //         user.imagePortrait = downloadUrl;
    //         await user.save();
    //     }

    //     return downloadUrl;
    // },
    // toggleActivateUser: async (idUser: string) => {
    //     const user = await userModel.findById(idUser);
    //     if (!user) {
    //         throw new Error("Lỗi khi sửa trạng thái user: Không tìm thấy user");
    //     }
    //     user.isActive = !user.isActive;
    //     await user.save();

    //     return user;
    // },
};

export default userService;
