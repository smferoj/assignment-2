const asyncHandler = require("express-async-handler");
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");




// Generate Token
const generateToken = (id) => {
  return jwt.sign({id}, process.env.JWT_SECRET, { expiresIn: "7d" });
};

// ================User Registration================
const registerUser = asyncHandler(async(req,res)=>{
  const {name, email,password}= req.body;

  // validation

  if(!name|| !email|| !password){
    res.status(400);
    throw new Error("Please fill all required fields");
  }

  if(password.length <6){
    res.status(400);
    throw new Error("Password must be upto 6 characters")
  };

   const userExists = await User.findOne({email});

  if(userExists){
    res.status(400)
    throw new Error("Email has alreadey been registered");
  }

  // create new user

  const user = await User.create({
    name,
    email,
    password,
  });

  // Generate Token

  const token = generateToken (user._id);

  // send in cookie

  res.cookie("token", token,{
    path: "/",
    httpOnly:true,
    expires: new Date(Date.now() + 7* 1000*86400),
    sameSite:'none',
    secure:true,
  });

  if (user){
    const {_id, name, email, photo, phone, bio} = user;

    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  }else{
    res.status(400);
    throw new Error("Invalid user data")
  }

});

// ===========login user=========

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validate Request
  if (!email || !password) {
    res.status(400);
    throw new Error("Please add email and password");
  }

  // Check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("User not found, please signup");
  }

  // User exists, check if password is correct
  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  //   Generate Token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "none",
    // secure: true,
  });

  if (user && passwordIsCorrect) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid email or password");
  }
});

// =============logout user========

// Logout User
const logout = asyncHandler(async(req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "Successfully Logged Out" });
});

// ===========get user data==========

const getUser = asyncHandler(async(req, res)=>{
  const user = await User.findById(req.user._id);

if(user){
  const {_id, name, email, photo, phone, bio} = user;

  res.status(200).json({
    _id,
    name,
    email,
    photo,
    bio,
  })
}else{
  res.status(400);
  throw new Error("User Not Found");
}

});

// ================get login status===========

const loginStatus = asyncHandler(async(req, res)=>{
  const token = req.cookies.token;

  if(!token){
    return res.json(false)
  }
  // verify token

  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if(verified){
    return res.json(true);

  }
  return res.json(false)
});

// ===========update user=============

const updateUser = asyncHandler(async(req, res)=>{
  const user = await User.findById(req.user._id);

  if(user){
    const {name, email, photo, phone, bio} = user;

    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      photo: updatedUser.photo,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
    });

  }else{
    res.status(404);
    throw new Error("User not found");
  }
})

// ===========change password=============

const changePassword = asyncHandler(async(req, res)=>{
  const user = await User.findById(req.user._id);
  const {oldPassword, password} = req.body;

  if(!user){
    res.status(400);
    throw new Error("User not found, please signup");
  }
  // validate

  if(!oldPassword || !password){
    res.status(400);
    throw new Error("Please add old and new password")
  }

  // check if  old password mathes password in DB

  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  // save new password

  if(user && passwordIsCorrect){
    user.password = password;
    await user.save();
    res.status(200).send("Password change successful");
  }else{
    res.status(400);
    throw new Error("Old password is incorrect")
  }
})







module.exports = {
  registerUser,
  loginUser,
  logout,
  getUser,
  loginStatus,
  updateUser
};