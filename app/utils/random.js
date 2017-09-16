/**
 * Created by SYLVAIN on 15/09/2017.
 */
'use strict';



//GENERATE RANDOM STRING FOR SALT
module.exports = function stringGen(len) {
    var text = " ";

    var charset = "abcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < len; i++)
        text += charset.charAt(Math.floor(Math.random() * charset.length));

    return text;
};



