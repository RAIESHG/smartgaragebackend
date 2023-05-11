function removeListString(fieldvalue){
    var newList = [];
    var fieldData = fieldvalue;
    console.log(fieldData + "FIELD Data");
    fieldData = fieldData.substring(1,fieldData.length-1);
    var splitdata = fieldData.split(",");
    for(var i = 0 ; i<splitdata.length;i++){
        newList.push(parseInt(splitdata[i]));
    }
    return newList;
}

module.exports = {removeListString};