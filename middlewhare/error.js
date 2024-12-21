import errorHandler from "../utils/errorHandler.js";

export default (err,req,res,next)=>{
    err.statusCode = err.statusCode || 500;
    err.message = err.message || "Internal server error"
    
    if (err.code === 11000) {
        const message = `${Object.keys(err.keyValue).join(", ")} already exists`;
        err = new errorHandler(message, 400);
    }

    if (err.name === "JsonWebTokenError") {
        err = new errorHandler("Invalid token, please log in again", 401);
    }

    if (err.name === "TokenExpiredError") {
        err = new errorHandler("Token has expired, please log in again", 401);
    }

    res.status(err.statusCode).json({
        success:false,
        message:err.message,
        stack:err.stack
    })
}