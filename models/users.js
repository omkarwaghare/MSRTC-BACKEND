// External Modules
const bcrypt = require('bcrypt');

// Local Modules
const { getDb } = require('../utils/databaseUtil');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('mongodb');

require('dotenv').config()

const SECRET_KEY = process.env.SECRET_KEY

module.exports = class User {


    //! Generates and return a token for authentication.
    static generateToken(insertedId) {

        const payload = {
            id: insertedId,
        };

        return jwt.sign(payload, SECRET_KEY);
    }

    //! This code verifies the token sent by the user

    static async verifyToken(token) {
        return jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) {
                return null;
            } else {
                return decoded.id
            }
        });
    }

    //! This block of code find as user in database for login by email id and return user info

    static async findUser(emailId) {
        const db = getDb();
        const userExist = await db.collection('users').find({
            'emailId': emailId,
        }).next();

        return userExist ? userExist : null
    }

    //! Check whether there is a user with same name or contact no in the database

    static async checkExistingUsers(contactNo, emailId) {
        const db = getDb();

        const contactNoExists = await db.collection('users').countDocuments({
            contactNo: contactNo
        });

        const emailIdExists = await db.collection('users').countDocuments({
            emailId: emailId
        });

        return contactNoExists === 0 && emailIdExists === 0 ? false : true
    }

    //! Checks whether OTP is already sent to specified email and OTP still valid

    static async checkExistingOTP(emailId) {
        const db = getDb();

        const OTPExists = await db.collection('otp').countDocuments({
            emailId: emailId,
        });

        return OTPExists > 0;
    }

    //! Hashes passwor and return hashed password

    static async hashPassword(password) {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        return hashedPassword;
    };

    //! Compare the password entered by the user with the hash code in the database

    static async comparePassword(enteredPassword, hashedPassword) {
        return await bcrypt.compare(enteredPassword, hashedPassword);
    };

    //! Hashes password and then add user in the database .

    static async addUser(name, contactNo, emailId, birthdate, password) {
        try {
            const db = getDb();


            const hashedPassword = await this.hashPassword(password.trim());

            const dataToInsert = {
                'studentName': name,
                'contactNo': contactNo,
                'emailId': emailId,
                'birthDate': birthdate,
                'password': hashedPassword

            }
            const result = await db.collection('users').insertOne(dataToInsert);

            if (!result.insertedId) {
                throw new Error("User insertion failed");
            }

            const insertedId = result.insertedId.toString();
            const token = User.generateToken(insertedId);

            dataToInsert.token = token;
            return dataToInsert;



        } catch (error) {
            throw new Error("There was an issue while adding information to the database");
        }
    }

    //! The following code will add user profile image to the database

    static async addProfileURL(imageURL, token) {
        const db = getDb();

        const decodedId = await this.verifyToken(token)

        return db.collection('users').updateOne({ _id: new ObjectId(String(decodedId.trim())) }, {
            $set: {
                'profileImageURL': imageURL,
            }
        });

    }

    //! Sends bus routes to the user
    static async sendBusRoutes() {
        const db = getDb();
        return db.collection('routes').find({}, { projection: { _id: 1, routeName: 1 } }).toArray();
    }

    //! Sends all bus stops for a bus route to the user 
    static async sendBusStops(routeId) {
        const db = getDb();
        const trimmedID = routeId.trim()

        return db.collection('routes').findOne({ _id: new ObjectId(trimmedID) }, { projection: { _id: 0, stops: 1 } });
    }

    //! Sends all institutes to the user
    static async sendInstitutes() {
        const db = getDb();
        return db.collection('institutes').find({}, { projection: { _id: 1, instituteName: 1 } }).toArray();
    }

    //! Adds student pass request in the database
    static async addUserPassApplication(userInfo, token) {
        const db = getDb();

        const decodedId = await this.verifyToken(token);

        if (!decodedId) {
            throw new Error("Invalid User token .");
        }

        return await db.collection('studentpasses').insertOne(userInfo);

    }

    //! Finds user pass data in users and studentpasses collection
    static async findUserPassData(token) {
        const db = getDb();

        const decodedId = await this.verifyToken(token)
        if (!decodedId) {
            throw new Error("Invalid User token .");
        }

        //! Left joins institute and users tables to the studentpasses table on instituteId and studentId
        const result = await db.collection('studentpasses').aggregate([
            {
                $match: {
                    studentId: decodedId.trim(),
                    collegeRemark: { $in: ['pending', 'approved'] }
                }
            },
            {
                $addFields: {
                    instituteIdObj: { $toObjectId: "$instituteId" },
                    studentIdObj: { $toObjectId: "$studentId" }
                }
            },
            {
                $lookup: {
                    from: 'institutes',
                    localField: 'instituteIdObj',
                    foreignField: '_id',
                    as: 'instituteDetails'
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
            { $unwind: { path: '$instituteDetails', preserveNullAndEmptyArrays: true } },
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
                    renewDate: 1,
                    expiryDate: 1,
                    travelPoints: 1,
                    collegeRemark: 1,
                    instituteName: '$instituteDetails.instituteName',
                    studentName: '$studentDetails.studentName',
                }
            }
        ]).toArray();


        return result.length > 0 ? result[0] : {};
    }

    //! Finds student data present in the studentpasses collection
    static async findUserById(studentId) {
        const db = getDb();
        return await db.collection('studentpasses').findOne({ studentId: studentId, collegeRemark: 'approved' })

    }

    //! Finds pass rate for given travelling points 
    static async findPassRate(points) {
        const db = getDb();
        return db.collection('passrates').findOne({ travellingPoints: String(points) })
    }

    //! Provides calculates new expiry date after 30 days
    static getNewExpiryDate = () => {
        const date = new Date();
        const newExpiry = date.setDate(date.getDate() + 30)
        return new Date(newExpiry).toISOString().split('T')[0]
    }

    //! update student pass data after the payment is successful 
    static async updateStudentPassData(studentId, dataToInsert) {
        try {
            const db = getDb();

            // New expiry and renewdates
            const date = new Date();
            const newRenewDate = date.toISOString().split('T')[0];
            const newExpiryDate = this.getNewExpiryDate();

            // Updates studentpass info and sets new renewdate and the expirydate
            const updatedPass = await db.collection('studentpasses').findOneAndUpdate({ studentId: studentId, collegeRemark: 'approved' }, {
                $set: {
                    renewDate: newRenewDate,
                    expiryDate: newExpiryDate
                }

            }, {
                returnDocument: "after"
            })

            // If there is no student to update the data
            if (!updatedPass) {
                return { success: false, message: "Not Such Student Pass Exist" }
            }

            // adds the payment info in the payments collection
            await db.collection('payments').insertOne({
                ...dataToInsert,
                renewDate: newRenewDate,
                timestamp: new Date(),
            });

            return { success: true, message: "Payment verified successfully", updatedPass }
        } catch (error) {
            return { success: false, message: "Server unable to process your request" }
        }

    }

    //! Adds punch in while going 
    static async addsGoingPassPunchData(token) {
        try {
            const db = getDb();

            const decodedId = await this.verifyToken(token);

            if (!decodedId) {
                return { status: 301, message: 'Incorrect Token Provided' }
            }

            const isPassActive = await db.collection('studentpasses').countDocuments({ studentId: decodedId, collegeRemark: 'approved' })
            if (isPassActive === 0) {
                return { status: 403, message: 'The student passes are disabled by the MSRTC for this academic year.' }
            }

            // const isGraceDateSet = 

            const dataToInsert = {
                studentId: decodedId,
                punchDate: new Date().toISOString().split('T')[0],
                punchTimeGoing: new Date().getTime(),
                going: 1
            }

            await db.collection('passpunches').insertOne(dataToInsert);
            return { status: 201, message: 'Pass Punched Successfully While Leaving', data: dataToInsert }
        } catch (error) {
            return { status: 500, message: 'Server is unable to process your request' }
        }

    }

    //! Adds punch in while returning
    static async addsReturningPassPunchData(token) {
        try {
            const db = getDb();

            const decodedId = await this.verifyToken(token);

            if (!decodedId) {
                return { status: 301, message: 'Incorrect Token Provided' }
            }

            let result = await db.collection('passpunches').findOneAndUpdate({ studentId: decodedId, punchDate: new Date().toISOString().split('T')[0] }, {
                $set: {
                    punchTimeReturning: new Date().getTime(),
                    returning: 1
                }
            },
                { returnDocument: 'after' }
            );

            // If result is null it means that the user has not travelled with bus while going

            if (!result) {
                const dataToInsert = {
                    studentId: decodedId,
                    punchDate: new Date().toISOString().split('T')[0],
                    going: 0,

                    punchTimeReturning: new Date().getTime(),
                    returning: 1
                }

                result = await db.collection('passpunches').insertOne(dataToInsert);

                return { status: 201, message: 'Pass Punched Successfully While Returning', data: dataToInsert }
            }

            return { status: 201, message: 'Pass Punched Successfully While Returning', data: result }

        } catch (error) {
            return { status: 500, message: 'Server is unable to process your request' }
        }
    }

    //! Find punch data 
    static async findPassPunchData(token) {
        const db = getDb();

        const decodedId = await this.verifyToken(token);

        if (!decodedId) {
            return { status: 301, message: 'Incorrect Token Provided' }
        }

        return await db.collection('passpunches').findOne({ studentId: decodedId, punchDate: new Date().toISOString().split('T')[0] });
    }

    //! Get validation dates 
    static async getValidationDatesForPass(token) {
        const db = getDb();

        const decodedId = await this.verifyToken(token);

        if (!decodedId) {
            return { status: 301, message: 'Incorrect Token Provided', data: {} }
        }

        const data = await db.collection('passvalidationdates').findOne({}, { projection: { _id: 0 } });
        return { status: 201, message: 'Data found', data: data || {} }
    }
}
