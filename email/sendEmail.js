
var nodemailer = require('nodemailer');

var transporter = nodemailer.createTransport({
  host: "smtpout.secureserver.net",
  port: 587, 
    auth: {
      user: 'info@sspeng.com',
      pass: 'Computer12.'
    }
  });

  
function sendEmail(subject, text, to) {
    transporter.sendMail({
      from: 'rghimire@sspeng.com',
      to: to,
      subject: subject,
      text: text
      , function(error, info) {
        // if (error) {
        //   console.log(error);
        // } else {
        //   console.log('Email sent: ' + info.response);
        // }
  
      }
    });
  }


  module.exports = {sendEmail};