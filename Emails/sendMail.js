const nodemailer = require("nodemailer");
require('dotenv').config()

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.HOST_EMAIL,
        pass: process.env.HOST_PASSWORD
    }
});


async function sendMail(emailId, OTP) {
    const result = await transporter.sendMail({
        from: process.env.HOST_EMAIL,
        to: emailId,
        subject: 'OTP ',
        html: `<!DOCTYPE html>
                <html>
                <head>
                    <style>
                        .container {
                            font-family: Arial, sans-serif;
                            padding: 20px;
                            border: 1px solid #ddd;
                            border-radius: 5px;
                            max-width: 400px;
                            margin: auto;
                            text-align: center;
                            background-color: #f9f9f9;
                        }
                        .otp {
                            font-size: 24px;
                            font-weight: bold;
                            color: #2d89ef;
                            margin: 10px 0;
                        }
                        .footer {
                            font-size: 12px;
                            color: #666;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Your OTP Code</h2>
                        <p>Use the following One-Time Password (OTP) to verify your identity:</p>
                        <p class="otp">${OTP}</p>
                        <p>This OTP is valid for 5 minutes. Do not share it with anyone.</p>
                        <p class="footer">If you did not request this OTP, please ignore this email.</p>
                        <p class="footer">Thank you,<br>MSRTC Team</p>
                    </div>
                </body>
                </html>
        `
    });

    return result;
}

module.exports = sendMail