import mongoose,{Schema} from 'mongoose'
import jwt from "jsonwebtoken"
import bcrypt from 'bcrypt'

const userSchema = new Schema({
    username:{
        type:String,
        required:true,
        unique:true,
        lowercase: true,
        trim: true,
        index:true
    },

    email:{
        type:String,
        required:true,
        unique:true,
        lowercase: true,
        trim: true,
    },

    fullname:{
        type:String,
        required:true,
        trim: true,
        index:true
    },

    avatar:{
        type: String,
        required: true,
    },
    coverImage:{
        type:String,
    },
    watchHistory:[
        {
            type:Schema.type.ObjectId,
            ref: "Video"
        }
    ],

    password:{
        type: String,
        required: [true,"Password is required"], 
    },
    refreshToken:{
        type: String
    }
},
{timestamps:true})

userSchema.pre("save",async function (next){
    if(!this.isModified("password")) return next();

    this.password = bcrypt.hash(this.password, 10)
})

userSchema.methods.ispasswordCorrect = async function (password){
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
    jwt.sign(
        {
            _id: this.id,
            email: this.email,
            username: this.username,
            fullname: this,fullname
        },
        process.env.ACCESS_TOKENS_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKENS_EXPIRY
        }
    )
}
userSchema.methods.generateRefreshToken = function(){
    jwt.sign(
        {
            _id: this.id,
            email: this.email,
            username: this.username,
            fullname: this,fullname
        },
        process.env.REFRESH_TOKENS_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKENS_EXPIRY
        }
    )
}

export const User = mongoose.model("User",userSchema)