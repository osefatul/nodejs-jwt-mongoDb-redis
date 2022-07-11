const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

let refreshTokens = [];
app.use(express.json());



const GenerateRefreshToken = (username) => {
  const refreshToken = jwt.sign({sub:username}, "refreshToken", {expiresIn: "15m"})
 //Check if there is any refresh token in the array.
  let storedRefreshToken = refreshTokens.find(x => x.username === username);

    // If not then add it to the array.
  if (storedRefreshToken === undefined) {
    refreshTokens.push({username: username, token:refreshToken})
  }
     // If founded then update the array.
  else {
    refreshTokens[refreshTokens.findIndex(x => x.username === username)].token = refreshToken
  }
  return refreshToken;

}


app.post("/api/login", function (req, res) {
  const { username, password } = req.body;
  if (username === "omar" && password === "12345") {
    const accessToken = jwt.sign({sub:username}, "accessToken", {
      expiresIn: "30s",
    });
    const refreshToken = GenerateRefreshToken(username)

    return res.json({
      status:true,
      message:"Login successful",
      data:{accessToken,refreshToken}
    });
  } 
  return res.status(401).json({status:false, message:"login failed"});

});


const verifyToken = (req, res, next) => {
  try {
    //Bearer tokenString
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, "accessToken");
    req.userData = decoded;
    next();

  }catch(error) {
return res.status(401).json({status:false, message:"your session is not valid", data:error})
  }
}
app.get ("/dashboard", verifyToken, (req, res) => {
  return res.status(200).json({status:true, message:"Hello!"});
})



const verifyRefreshToken = (req, res, next) => {
  const token = req.body.token;
  if (token === null) return res.status(401).json({status:false, message:"invalid request"})
  try {
    const decoded = jwt.verify(token, "refreshToken");
    req.userData = decoded;

    // verify the refresh token is in store or not
    let storedRefreshToken = refreshTokens.find (x=> x.username === decoded.sub);
    if (storedRefreshToken === undefined) return res.status(401).json({status:false, message:"Invalid Request"})
    // check if the refresh token is from old one or has been updated from token page. every time token request sent, refresh token is updated.
    if (storedRefreshToken.token !== token) return res.status(401).json({status:false, message:"Refresh token is not the same as the stored refresh token"})
    next();

  }catch(error) {
return res.status(401).json({status:false, message:"your session is not valid", data:error})
  }}




app.post("/token",verifyRefreshToken, (req, res)=> {
  const username = req.userData.sub;
  const accessToken = jwt.sign({sub:username}, "accessToken", {
    expiresIn: "30s",
  });
  const refreshToken = GenerateRefreshToken(username)
    return res.json({
      status:true,
      message:" successful",
      data:{accessToken,refreshToken}
    });
} )




app.get ("/logout", verifyToken, (req, res) => {
  //this will have accessToken in the authorization.
  const username = req.userData.sub;

  // remove the refresh token
  refreshTokens = refreshTokens.filter(x => x.username !== username);
  return res.json({status:true, message:" successfully logout"} )

})

app.listen(6000, () => console.log("backend is running"));
