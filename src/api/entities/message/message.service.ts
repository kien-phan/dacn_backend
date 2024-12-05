import mongoose from "mongoose";
import firebaseImageActions from "../../helpers/firebaseImageActions";
import { isImageOrVideo } from "../../middlewares/multer";
import messageModel from "./message.model";
import { MessageCreateInterface } from "../../../core";
import conversationModel from "../conversation/conversation.model";
import postService from "../post/post.service";

const messageService = {
    getMessages: async (conversationId: string, messageId: string) => {
        // Lấy ra message để tìm timestamp (createdAt) của nó
        const lastMessage = await messageModel.findById(messageId);
        if (!lastMessage) {
            throw new Error("Message not found");
        }

        // Query để lấy các message cũ hơn
        const oldMessages = await messageModel
            .find({
                conversation: conversationId,
                createdAt: { $lt: lastMessage.createdAt }, // Các message tạo trước thời điểm message hiện tại
            })
            .sort({ createdAt: -1 }) // Sắp xếp theo thời gian giảm dần (mới nhất trước)
            .limit(20)
            .populate("sender forwardFrom")
            .exec(); // Giới hạn 20 tin nhắn

        return oldMessages;
    },
    getAllMessageOfAnConversation: async (conversationId: string) => {
        const messages = await messageModel
            .find({ conversation: conversationId })
            .sort({ createdAt: -1 })
            .populate("sender forwardFrom")
            .exec();

        return messages;
    },
    createMesage: async (data: MessageCreateInterface) => {
        const session = await mongoose.startSession();
        let newMessage;
        await session.withTransaction(async () => {
            if (data.sender) {
                data.sender = new mongoose.Types.ObjectId(data.sender);
            }
            if (data.forwardFrom && data.forwardFrom.toString().trim() !== "") {
                data.forwardFrom = new mongoose.Types.ObjectId(
                    data.forwardFrom
                );
            } else {
                delete data.forwardFrom; // Loại bỏ trường này nếu nó không hợp lệ
            }
            if (data.conversation) {
                data.conversation = new mongoose.Types.ObjectId(
                    data.conversation
                );
            }

            const message = new messageModel(data);

            await message.save();
            await message.populate("sender forwardFrom");

            // update last message
            const conversation = await conversationModel
                .findByIdAndUpdate(
                    message.conversation,
                    { lastMessage: message._id },
                    { new: true }
                )
                .populate([
                    { path: "participants" }, // Populate participants
                    {
                        path: "lastMessage",
                        populate: { path: "sender" }, // Nested populate: lastMessage.sender
                    },
                ])
                .exec();
            newMessage = {
                message: message,
                conversation: conversation,
            };
        });
        session.endSession();
        return newMessage;
    },
    readMessage: async (messageId: string, userId: string) => {
        const message = await messageModel.findById(messageId);

        if (!message) {
            return null;
        }

        if (message.sender.equals(userId)) {
            // Không thực hiện gì nếu là tin nhắn của chính user
            return null;
        }

        message.isRead = true; // Đánh dấu đã đọc
        await message.save(); // Lưu thay đổi
        await message.populate("sender forwardFrom"); // Populate dữ liệu liên quan
        return message;
    },
    deleteMessage: async (messageId: string) => {
        const message = await messageModel
            .findByIdAndUpdate(
                messageId,
                { content: "Tin nhắn đã được thu hồi" },
                { new: true }
            )
            .populate("sender forwardFrom")
            .exec();

        if (message && message.medias && message.medias.length > 0) {
            const mediaSources = message.medias.map((media) => media.source);
            await postService.deleteImages(mediaSources);
        }

        return message;
    },
    uploadMessageFiles: async (medias: Express.Multer.File[]) => {
        const dataRes: {
            type: string;
            source: string;
            fileName: string;
        }[] = await Promise.all(
            medias.map(async (media) => {
                const type = isImageOrVideo(media);

                if (!type)
                    throw new Error(`File Type Error: ${media.originalname}`);
                const downloadUrl =
                    await firebaseImageActions.uploadImageToFirebase(
                        media,
                        "single",
                        `dacn_messageFiles`
                    );

                if (!downloadUrl)
                    throw new Error(`Upload Error: ${media.originalname}`);
                return {
                    type: type,
                    source: downloadUrl,
                    fileName: media.originalname,
                };
            })
        );

        return dataRes;
    },
};

export default messageService;
