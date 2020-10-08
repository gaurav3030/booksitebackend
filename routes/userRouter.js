const router = require("express").Router();
const User = require("../modules/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("../middleware/auth");

router.post("/register",async (req,res) => {

    try{
        const {email , password, passwordCheck ,username} = req.body;
    
        //validation
    
        if(!email || !password || !passwordCheck || !username){
            return res.status(400).json({msg: "not all fields are returned"});
        }
        if (password.length <6)
            return res.status(400).json({msg: "password should be at least 6 character long"});
        if( password != passwordCheck)
            return res.status(400).json({msg: "enter same password twice"});
        const existingUser = await User.findOne({email: email});
        if(existingUser){
            return res.status(400).json({msg: "Email already has a account"});
        }

        //hashing

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password,salt);
        
        const newUser = new User({
            email,
            password : passwordHash,
            username
        });
        const savedUser = await newUser.save();
        res.json(savedUser);
    }catch(err){
        res.status(500).json({error: err.message});
    }
    
});



router.post("/login", async (req,res) =>{
    try{
        const {email , password} = req.body;
        //validate
        if(!email || !password){
            return res.status(400).json({msg: "not all fields are returned"});
        }
        const existingUser = await User.findOne({email: email});
        if(!existingUser){
            return res.status(400).json({msg: "email not registered"});
        }

        const isMatch = await bcrypt.compare(password,existingUser.password);
        if(!isMatch){
            return res.status(400).json({msg: "incorrect credentials"});
        }

        const token = jwt.sign({ id:existingUser._id }, process.env.JWT_TOKEN);
        res.json({
            token,
            user:{
                id:existingUser._id,
                username : existingUser.username,
            }
        })

    }catch(err){
        res.status(500).json({error: err.message});
    }
    
});

router.delete("/delete", auth ,async (req,res)=>{
    try{
        const deletedUser = await User.findByIdAndDelete(req.user);
        res.json(deletedUser);
    }catch(err){
        res.status(500).json({error: err.message});
    }
});

router.post("/tokenIsValid", async (req,res)=>{
    try{
        const token = req.header("x-auth-token");
        if(!token) return res.json(false);

        const verified = jwt.verify(token, process.env.JWT_TOKEN);
        if(!verified) return res.json(false);
        
        const user = await User.findById(verified.id);
        if(!user) return res.json(false);
        return res.json(true);
    }catch(err){
        res.status(500).json({error: err.message});
    }
});

module.exports = router;