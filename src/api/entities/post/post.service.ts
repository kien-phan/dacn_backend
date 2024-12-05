import mongoose from "mongoose";

import postModel from "./post.model";
import relationshipModel from "../relationship/relationship.model";
import commentModel from "../postComment/postComment.model";
import firebaseImageActions from "../../helpers/firebaseImageActions";
import { PostCreateInterface } from "../../../core";
import { isImageOrVideo } from "../../middlewares/multer";
import postInteractedModel from "../postInteracted/postInteracted.model";

const postService = {
    getAllPosts: async () => {
        return await postModel.find().lean();
    },
    listPostsAdvance: async (userId: string, viewedPosts: string[] = []) => {
        const limit = 10;
        const threeDaysAgo = new Date();
        threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);

        // tìm post dựa trên relationship
        const relationships = await relationshipModel
            .find({
                user1: userId,
                relationship: { $in: ["friend", "following"] },
            })
            .select("user2");

        const relatedUserIds = relationships.map((rel) => rel.user2);

        const posts = await postModel
            .find({
                author: { $in: relatedUserIds }, // Bài viết từ bạn bè và người đang theo dõi
                _id: { $nin: viewedPosts }, // Loại bỏ bài viết đã xem
                createdAt: { $gte: threeDaysAgo },
            })
            .sort({ createdAt: -1 }) // Sắp xếp bài viết mới nhất
            .limit(limit)
            .populate("author collaborators")
            .exec();

        // Nếu chưa đủ bài viết, thêm bài viết có `score` cao
        if (posts.length < limit) {
            const extraPosts = await postModel
                .find({
                    _id: { $nin: [...viewedPosts, ...posts.map((p) => p._id)] },
                    createdAt: { $gte: threeDaysAgo },
                })
                .sort({ score: -1 }) // Lấy bài viết có score cao
                .limit(limit - posts.length)
                .populate("author collaborators")
                .exec();

            posts.push(...extraPosts);
        }

        return posts;
    },
    getOnePostById: async (postId: string) => {
        const post = await postModel
            .findById(postId)
            .populate("author collaborators")
            .exec();

        return post;
    },
    getPostOfOneUser: async (userId: string) => {
        const posts = await postModel
            .find({ author: userId })
            .populate("author collaborators")
            .exec();

        return posts;
    },
    uploadPostFiles: async (medias: Express.Multer.File[]) => {
        const dataRes: {
            type: string;
            source: string;
        }[] = await Promise.all(
            medias.map(async (media) => {
                const type = isImageOrVideo(media);

                if (!type)
                    throw new Error(`File Type Error: ${media.originalname}`);
                const downloadUrl =
                    await firebaseImageActions.uploadImageToFirebase(
                        media,
                        "single",
                        `dacn_postFiles`
                    );

                if (!downloadUrl)
                    throw new Error(`Upload Error: ${media.originalname}`);
                return {
                    type: type,
                    source: downloadUrl,
                };
            })
        );

        return dataRes;
    },
    createOnePost: async (data: PostCreateInterface) => {
        const session = await mongoose.startSession();
        let newPost;
        await session.withTransaction(async () => {
            if (data.author) {
                data.author = new mongoose.Types.ObjectId(data.author);
            }

            if (data.collaborators) {
                data.collaborators = data.collaborators.map(
                    (clbrtorId) => new mongoose.Types.ObjectId(clbrtorId)
                );
            }

            const post = new postModel(data);

            await post.save();
            await post.populate("author collaborators");
            newPost = post;
        });
        session.endSession();
        return newPost;
    },
    updateOnePost: async (postId: string, data: PostCreateInterface) => {
        const session = await mongoose.startSession();
        let newPost;
        await session.withTransaction(async () => {
            // delete old files
            const oldPost = await postModel.findById(postId).lean();

            if (!oldPost) throw new Error(`Không tìm thấy post: ${postId}`);

            if (oldPost.medias && oldPost.medias.length > 0) {
                const removedFileUrls = oldPost.medias
                    .map((oldFile) => oldFile.source)
                    .filter(
                        (source): source is string =>
                            source !== null && source !== undefined
                    ); // Lọc bỏ null và undefined

                await postService.deleteImages(removedFileUrls); // removedFileUrls bây giờ chỉ chứa string[]
            }

            // update
            if (data.author) {
                data.author = new mongoose.Types.ObjectId(data.author);
            }

            newPost = await postModel
                .findByIdAndUpdate(postId, data)
                .populate("author collaborators")
                .exec();
        });
        session.endSession();
        return newPost;
    },
    deleteOnePost: async (postId: string) => {
        const session = await mongoose.startSession();

        let newPost;
        await session.withTransaction(async () => {
            const post = await postModel.findByIdAndDelete(postId);

            if (!post) {
                throw new Error(
                    "Lỗi khi xoá bài viết: Không tìm thấy bài viết "
                );
            }

            // delete images from firebase
            let medias: string[] = [];
            if ("medias" in post && post.medias) {
                post.medias.forEach((media) => {
                    if (media.source) medias.push(media.source);
                });
            }

            await postService.deleteImages(medias);

            await commentModel.deleteMany({ postId });

            newPost = post;
        });

        session.endSession();

        return newPost;
    },
    deleteImages: async (medias: string[] = []) => {
        if (medias.length > 0) {
            await Promise.all(
                medias.map(async (url) => {
                    await firebaseImageActions
                        .deleteFileFromFireBase(url)
                        .catch((err: any) => {
                            console.log(
                                `Error delete image of post: ${url}, [${err.message}]`
                            );
                        });
                })
            );
        }
    },

    // Interact
    likePost: async (userId: string, postId: string) => {
        const session = await mongoose.startSession();
        await session.withTransaction(async () => {
            // check
            const isExist = await postInteractedModel.findOne({
                user: userId,
                post: postId,
            });

            if (!isExist) {
                // Nếu chưa tồn tại, tạo tương tác mới
                const likePost = new postInteractedModel({
                    user: new mongoose.Types.ObjectId(userId),
                    post: new mongoose.Types.ObjectId(postId),
                });

                await likePost.save();

                // Tăng likeNum của post
                await postModel.findByIdAndUpdate(
                    postId,
                    { $inc: { likeNum: 1, score: 1 } }, // Tăng 1
                    { new: true }
                );
            } else {
                // Nếu đã tồn tại, xóa tương tác
                await postInteractedModel.deleteOne({ _id: isExist._id });

                // Giảm likeNum của post
                await postModel.findByIdAndUpdate(
                    postId,
                    { $inc: { likeNum: -1, score: -1 } }, // Giảm 1
                    { new: true }
                );
            }
        });

        session.endSession();
    },
};

export default postService;
