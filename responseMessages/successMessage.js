


function returnSucess(json,message,res){
    return res.json({
        data:json,
        message:message,
        status:true
    });
}


module.exports = {returnSucess};