// External Modules
const bcrypt = require('bcrypt');

// Local Modules
const { getDb } = require('../utils/databaseUtil');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('mongodb');

require('dotenv').config()

const SECRET_KEY = process.env.SECRET_KEY

module.exports = class College {


    //! Generates and return a token for authentication.
    static generateToken(instituteId, emailId, role) {

        const payload = {
            instituteId: instituteId.toString(),
            emailId: emailId,
            role: role
        };

        return jwt.sign(payload, SECRET_KEY);
    }

    //! This code verifies the token sent by the user

    static async verifyToken(token) {
        return jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) {
                return null;
            } else {
                return decoded
            }
        });
    }

    //! This block of code find as user in database for login by email id and return user info

    static async findCollege(emailId) {
        const db = getDb();
        const userExist = await db.collection('institutes').find({
            'instituteEmailId': emailId,

        }).next();

        return userExist ? userExist : null
    }


    //! Checks whether OTP is already sent to specified email and OTP still valid

    static async checkExistingOTP(emailId) {
        const db = getDb();

        const OTPExists = await db.collection('otp').countDocuments({
            emailId: emailId,
        });

        return OTPExists > 0;
    }


    //! Hashes password and return hashed password

    static async hashPassword(password) {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        return hashedPassword;
    };


    //! Compare the password entered by the user with the hash code in the database

    static async comparePassword(enteredPassword, hashedPassword) {
        return await bcrypt.compare(enteredPassword, hashedPassword);
    };

    //! Validates the admin by checking token and database admin credentials

    static async collegeValidation(token) {

        const db = getDb();
        const isValidToken = await this.verifyToken(token)

        const { emailId } = isValidToken

        // checks the admin is real or not
        const college = await db.collection('institutes').findOne({ instituteEmailId: emailId });

        if (!college || isValidToken.role !== 'user') {
            return false
        }

        return true;
    }

    //! Sends student data to the institute
    static async getPendingPassApplications(token) {
        const decodedToken = await this.verifyToken(token);

        if (!decodedToken) {
            return { status: 401, message: 'Invalid Token..!' };
        }

        const { instituteId } = decodedToken;
        const db = getDb();

        const pendingApplications = await db.collection('studentpasses').aggregate([
            {
                $match: {
                    instituteId: instituteId.trim(),
                    collegeRemark: 'pending'
                }
            },
            {
                $addFields: {
                    studentIdObj: { $toObjectId: "$studentId" }
                }
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'studentIdObj',
                    foreignField: '_id',
                    as: 'studentDetails'
                }
            },
            { $unwind: { path: '$studentDetails', preserveNullAndEmptyArrays: true } },
            {
                $project: {
                    _id: 0,
                    studentId: 1,
                    class: 1,
                    division: 1,
                    address: 1,
                    from: 1,
                    to: 1,
                    travelPoints: 1,
                    collegeRemark: 1,
                    studentName: '$studentDetails.studentName',
                    profileImageURL: '$studentDetails.profileImageURL',
                    birthDate: '$studentDetails.birthDate'
                }
            }
        ]).toArray();

        return { status: 201, message: 'success', pendingApplications }
    }

    //! Change the status of the student pass application according to the college authority's instruction
    static async approveRejectApplication(studentId, action) {
        const db = getDb();

        if (action === 'approve') {
            const result = await db.collection('studentpasses').updateOne({ studentId: studentId.trim() }, { $set: { collegeRemark: 'approved' } })
            return { status: 201, message: 'Pass Application Approved' };
        } else {
            const result = await db.collection('studentpasses').updateOne({ studentId: studentId.trim() }, { $set: { collegeRemark: 'rejected' } })
            return { status: 201, message: 'Pass Application Rejected' };
        }


    }

}