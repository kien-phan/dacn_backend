import mongoose from "mongoose";
import { CommentCreateDataInterface } from "../../../core";
import postCommentModel from "./postComment.model";
import postModel from "../post/post.model";

const postCommentService = {
    getAllPostComments: async () => {
        return await postCommentModel.find().lean();
    },
    createComment: async (data: CommentCreateDataInterface) => {
        // create comment
        const newComment = new postCommentModel({
            ...data,
            parent: data.parent
                ? new mongoose.Types.ObjectId(data.parent)
                : null,
            replyTo: data.replyTo
                ? new mongoose.Types.ObjectId(data.replyTo)
                : null,
        });

        await newComment.save();
        // check if cmt has parent. Yes: update chilren num of parent cmt. ortherwise
        if (data.parent) {
            await postCommentModel.findByIdAndUpdate(data.parent, {
                $inc: { childrenNum: 1 },
            });
        }

        // update post cmtnum
        await postModel.findByIdAndUpdate(data.post, {
            $inc: { commentNum: 1 },
        });

        return newComment;
    },
    getParentCmt: async (postId: string, skip = 0) => {
        const comments = await postCommentModel
            .find({
                post: postId, // Chỉ lấy comment của bài post cụ thể
                parent: null, // Comment không có parent (comment gốc)
            })
            .sort({ createdAt: -1 }) // Sắp xếp theo thời gian giảm dần (mới nhất trước)
            .skip(skip)
            .limit(10) // Giới hạn kết quả trả về
            .populate("user replyTo") // Lấy thêm thông tin user (ví dụ: name)
            .lean()
            .exec(); // Trả về object JavaScript thay vì document Mongoose

        return comments;
    },
    getChildrenCmt: async (parentId: string, skip = 0) => {
        const cmts = await postCommentModel
            .find({ parent: parentId })
            .sort({ createdAt: -1 }) // Sắp xếp theo thời gian giảm dần (mới nhất trước)
            .skip(skip)
            .limit(10) // Giới hạn kết quả trả về
            .populate("user replyTo") // Lấy thêm thông tin user (ví dụ: name)
            .lean()
            .exec();

        return cmts;
    },
    deleteCmt: async (cmtId: string) => {
        // Kiểm tra comment tồn tại
        const comment = await postCommentModel.findById(cmtId);
        if (!comment) {
            throw new Error("Không tìm thấy comment");
        }

        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
            const { post, parent, childrenNum } = comment;

            // Xóa tất cả comment con (nếu có)
            if (childrenNum > 0) {
                await postCommentModel.deleteMany({ parent: cmtId });
            }

            // Xóa comment hiện tại
            await postCommentModel.findByIdAndDelete(cmtId);

            // Cập nhật số lượng comment ở bài post hoặc parent
            if (parent) {
                // Giảm `childrenNum` của comment cha
                await postCommentModel.findByIdAndUpdate(parent, {
                    $inc: { childrenNum: -1 },
                });
            } else {
                // Giảm `commentNum` của bài post
                await postModel.findByIdAndUpdate(post, {
                    $inc: { commentNum: -1 },
                });
            }
        });

        return comment;
    },
};

export default postCommentService;
