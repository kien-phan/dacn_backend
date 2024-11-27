import mongoose from "mongoose";
import chatChannelModel from "./chatChannel.model";
import userModel from "../user/user.model";

const chatChannelService = {
    addChannel: async (participants: string[]) => {
        // Chuyển đổi các participant IDs thành ObjectId
        const participantObjectIds = participants.map(
            (id) => new mongoose.Types.ObjectId(id)
        );

        // Kiểm tra xem channel có tồn tại với các participant này chưa
        const existingChannel = await chatChannelModel.findOne({
            participants: { $all: participantObjectIds }, // Kiểm tra nếu tất cả participants có trong một channel
            $expr: {
                $eq: [{ $size: "$participants" }, participantObjectIds.length],
            }, // Đảm bảo số lượng participants khớp chính xác
        });

        if (existingChannel) {
            return;
        }

        // Nếu chưa tồn tại, tạo channel mới
        const newChannel = new chatChannelModel({
            participants: participantObjectIds,
        });
        await newChannel.save();

        // update user
        await userModel.updateMany(
            { _id: { $in: participants } }, // Tìm tất cả các user có `_id` trong mảng `participants`
            {
                $push: {
                    channels: new mongoose.Types.ObjectId(newChannel._id),
                },
            }
        );

        // ping to socketio

        return;
    },
    deleteChannelById: async (channelId: string) => {
        // Kiểm tra tính hợp lệ của channelId
        if (!mongoose.Types.ObjectId.isValid(channelId)) {
            throw new Error("Invalid channelId");
        }

        // Xóa channel
        const channel = await chatChannelModel.findByIdAndDelete(channelId);

        // Nếu channel tồn tại, cập nhật thông tin user
        if (channel && channel.participants?.length > 0) {
            await userModel.updateMany(
                { _id: { $in: channel.participants } }, // Tìm tất cả các user có `_id` trong mảng `participants`
                {
                    $pull: {
                        channels: channel._id, // Xóa channel khỏi danh sách `channels` của user
                    },
                }
            );
        }

        return channel; // Trả về channel đã xóa (hoặc `null` nếu không tồn tại)
    },
};

export default chatChannelService;
