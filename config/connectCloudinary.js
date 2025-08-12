import { v2 as cloudinary } from 'cloudinary'
import { CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET, CLOUDINARY_CLOUD_NAME } from './env.js';


const connectCloudinary = async () => {
    try {
        await cloudinary.config({
            cloud_name: CLOUDINARY_CLOUD_NAME,
            api_key: CLOUDINARY_API_KEY,
            api_secret: CLOUDINARY_API_SECRET
        })
    } catch (error) {
        console.log(error);
        
    }
}

export default connectCloudinary