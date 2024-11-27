import multer from "multer";

//
export const uploadMultiple = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10000000 }, // 10 MB
    fileFilter: async function (req, file, cb) {
        checkFileType(file, cb);
    },
});

//
export const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 1048576 * 10 }, // 10 MB
    fileFilter: async function (req, file, cb) {
        checkFileType(file, cb);
    },
});

// Check file Type
export function checkFileType(
    file: Express.Multer.File,
    cb: multer.FileFilterCallback
) {
    // Check mime
    const allowedMimeTypes =
        /^(image\/(jpeg|jpg|png|gif)|video\/(mp4|avi|mpeg|quicktime))$/i;
    const mimeType = allowedMimeTypes.test(file.mimetype);

    if (mimeType) {
        return cb(null, true);
    } else {
        cb(
            new Error(
                "Only Images (JPEG, JPG, PNG, GIF) and Videos (MP4, AVI, MPEG, MOV) are allowed!!!"
            )
        );
    }
}

export function isImageOrVideo(file: Express.Multer.File): string | null {
    const imageMimeTypes = /^image\/(jpeg|jpg|png|gif|webp|bmp)$/i;
    const videoMimeTypes = /^video\/(mp4|avi|mpeg|quicktime|webm|mkv)$/i;

    if (imageMimeTypes.test(file.mimetype)) {
        return "image"; // Tệp là hình ảnh
    } else if (videoMimeTypes.test(file.mimetype)) {
        return "video"; // Tệp là video
    } else {
        return null; // Không phải hình ảnh hoặc video
    }
}
