// const router = require("express").Router();
// const { PrismaClient, prisma } = require('@prisma/client');
// const { } = new PrismaClient();
// const {setHeaders} = require('../components/setHeaders.js');


// router.get('/', async (req, res,con) => {
//     // auth.verifyToken(req,res,()=>changeAccess(req,res));
//     changeAccess(req,res,con);
  
// })

// async function changeAccess(req,res){
//     setHeaders(res);
//     try {
//         router.query("SELECT * FROM user", function(err, row) {


//         res.json({data: 'Access Granted Success', message: "Successfully Fetched", status: true});


//         });
       
        
//     } catch (e) {
//         console.log(e);
//         res.json({data: "", message: "Something Went Wrong Please Try Again", status: false});
//     }

// }

// module.exports = router;