const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

require("dotenv").config();


const app =express();
app.use(express.json());
app.use(cors());

const PORT = 5000 || process.env.port;

app.listen(PORT, ()=>{
    console.log("server is running at "+ PORT);
});

//setupmongoose

mongoose.connect(process.env.MONGODB_CONNECTION_STRING, {
    useNewUrlParser:true,
    useUnifiedTopology:true,
    useCreateIndex:true,
}, (err) => {
    if(err) throw err;
    console.log("Mongodb connection established");
});

//set routes

app.use("/users",require("./routes/userRouter"));