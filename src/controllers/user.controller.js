import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
const cookieOptions = {
    httpOnly: true,
    secure: true,
};

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({
            validateBeforeSave: false,
        });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(
            500,
            "Something went wrong while generating access and refresh token"
        );
    }
};

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

    if (
        [fullName, username, email, password].some(
            (field) => field?.trim() == ""
        )
    ) {
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (existedUser) {
        throw new ApiError(409, "User already exists");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (
        req.files &&
        Array.isArray(req.files.coverImage) &&
        req.files.coverImage.length > 0
    ) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar image is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Avatar image is required");
    }

    const user = await User.create({
        fullName,
        username: username.toLowerCase(),
        email,
        password,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if (!createdUser) {
        throw new ApiError(
            500,
            "Something went wrong while registering user!!!"
        );
    }

    return res
        .status(201)
        .json(
            new ApiResponse(201, createdUser, "User registered successfully")
        );
});

const loginUser = asyncHandler(async (req, res) => {
    // 1. req.body -> data
    // 2. username or email
    // 3. find user in db
    // 4. password check
    // 5. generate access token and refresh token
    // 6. send cookie
    // 7. return response

    const { username, email, password } = req.body;

    if (!(username || email)) {
        throw new ApiError(400, "username or email is required");
    }

    const user = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (!user) {
        throw new ApiError(404, "User does not exist!!!");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(400, "Invalid user credentials");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
        user._id
    );

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    return res
        .status(200)
        .cookie("accessToken", accessToken, cookieOptions)
        .cookie("refreshToken", refreshToken, cookieOptions)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken,
                },
                "User logged in successfully!!!"
            )
        );
});

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            refreshToken: undefined,
        },
        {
            new: true,
        }
    );

    

    return res
        .status(200)
        .clearCookie("accessToken", cookieOptions)
        .clearCookie("refreshToken", "", cookieOptions)
        .json(new ApiResponse(
            200, 
            {}, 
            "User logged out successfully!!!"
        ));

});

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies?.refreshToken || req.body.refreshToken ;
    
        if (!incomingRefreshToken) {
            throw new ApiError(401, "Unauthorized request");
        }
    
        const decodedToken = await jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
    
        if (!decodedToken) {
            throw new ApiError(401, "Unauthorized request");
        }
    
        const user = await User.findById(decodedToken?._id);
    
        if (!user) {
            throw new ApiError(401, "Invalid Refresh Token");
        }
    
        if(incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh Token does not match || refresh token expired");
        }
    
        const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id);
    
        res
            .status(200)
            .cookie("accessToken", accessToken, cookieOptions)
            .cookie("refreshToken", refreshToken, cookieOptions)
            .json(new ApiResponse(
                200, 
                {}, 
                "Access Token refreshed successfully!!!"
            ));
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Refresh Token");
    }
});

export { registerUser, loginUser, logoutUser, refreshAccessToken };