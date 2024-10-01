import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import {ApiResponse} from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) => {
    // 1. get user detatils from frontend
    // 2. validation - not empty 
    // 3. check if user already exists or not: username, email
    // 4. check for images, check for avatar
    // 5. upload them to cloudinary
    // 6. create user object - create entry in db
    // 7. remove password and refresh token feild from response
    // 8. check for user created or not
    // 9. return response
    
    const { fullName, username, email, password } = req.body;

    if(
        [fullName, username, email, password].some((field) => field?.trim() == "")
    ){
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [
            { username },
            { email }
        ]
    });

    if(existedUser){
        throw new ApiError(409, "User already exists");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;    

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar image is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar image is required");
    }

    const user = await User.create({
        fullName,
        username : username.toLowerCase(),
        email,
        password,
        avatar : avatar.url,
        coverImage : coverImage?.url || "",
    })

    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering user!!!");
    }

    return res.status(201).json(
        new ApiResponse(201, createdUser, "User registered successfully")
    )

})

export { registerUser }