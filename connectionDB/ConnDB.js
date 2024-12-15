import mongoose from "mongoose";

const connectDB = ()=>{
    mongoose.connect(process.env.MONGODB_URL)
    .then(()=>{
        console.log("Backend Connected...")
    })
    .catch((err)=>{
        console.log(`Error in connecting Backend... ${err.message}`)
    })
}

export default connectDB;