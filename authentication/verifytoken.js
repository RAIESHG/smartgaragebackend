var jwt = require('jsonwebtoken');



function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
  
    if (bearerHeader) {
      const bearer = bearerHeader.split(' ');
      const bearerToken = bearer[1];
      jwt.verify(bearerToken,"citygreen",function(err,decoded){
        if(err){
          res.json({data:"",message:"UnAuthorized Access Forbidden",status:false});

        }
        else{
         next();
        }
      })
    
    } else {
      // res.sendStatus(403);
      res.json([{data:"",message:"UnAuthorized Access Forbidden",status:false}]);

    }
}

module.exports = {verifyToken};