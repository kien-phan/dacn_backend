import mongoose from "mongoose";

import defaultValues from "../api/helpers/DefaultValues";

const databases = {
    mongodb: {
        connect: async function () {
            try {
                mongoose.set("strictQuery", false);

                mongoose.connection.on("connected", () => {
                    console.log("on connected");
                });

                await mongoose
                    .connect(process.env.MONGODB_URL as string, {
                        retryWrites: true, // thử kết nối lại trong trường hợp ghi thất bại
                        maxStalenessSeconds: 10, // chờ đợi tối đa 10 giây khi kết nối bị mất
                    })
                    .then(() => {
                        defaultValues();
                    });

                mongoose.connection.on("error", (err) => {
                    console.log("[DB error]", err.message);
                });

                mongoose.connection.on("disconnected", () => {
                    console.log("[DB disconnected] Connection is disconnected");
                });

                process.on("SIGINT", async () => {
                    await mongoose.connection.close();
                    process.exit(0);
                });
            } catch (error: any) {
                console.log("[DB]", error.message);
            }
        },
    },
};

export default databases;
