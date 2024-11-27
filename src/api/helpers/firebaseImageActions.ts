import {
    deleteObject,
    getDownloadURL,
    getStorage,
    ref,
    uploadBytes,
} from "firebase/storage";
import { FileQuantityType } from "../../core";

const firebaseImageActions = {
    uploadImageToFirebase: async (
        file: Express.Multer.File | Express.Multer.File[],
        quantity: FileQuantityType,
        folder: string
    ) => {
        const storageFB = getStorage();

        if (quantity === "single" && !Array.isArray(file)) {
            const dateTime = Date.now();
            const fileName = `${folder}/${dateTime}`;
            const storageRef = ref(storageFB, fileName);
            const metadata = {
                contentType: file.mimetype,
            };
            console.log("start upload");
            console.log(file, "[file]");
            console.log(metadata, "[metadata]");

            let ImageURL = "";
            await uploadBytes(storageRef, file.buffer, metadata).then(
                async () => {
                    ImageURL = await getDownloadURL(storageRef);
                }
            );
            return ImageURL;
        }

        if (quantity === "multiple" && Array.isArray(file)) {
            for (let i = 0; i < file.length; i++) {
                const dateTime = Date.now();
                const fileName = `${folder}/${dateTime}`;
                const storageRef = ref(storageFB, fileName);
                const metadata = {
                    contentType: file[i].mimetype,
                };

                await uploadBytes(storageRef, file[i].buffer, metadata);
            }
            return;
        }
    },

    deleteFileFromFireBase: async (downloadUrl: string) => {
        const storageFB = getStorage();
        const fileRef = ref(storageFB, downloadUrl);
        await deleteObject(fileRef);
    },
};

export default firebaseImageActions;
