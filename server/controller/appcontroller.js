import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import otpGenerator from 'otp-generator';
import det from '../model/details.model.js';
import UserModel from '../model/user.model.js';
import ENV from '../router/config.js';
/** POST: http://localhost:8080/api/register
 * @param : {
  "username" : "example123",
  "password" : "admin123",
  "email": "example@gmail.com",
  "firstName" : "bill",
  "lastName": "william",
  "mobile": 8009860560,
  "address" : "Apt. 556, Kulas Light, Gwenborough",
  "profile": ""
}
*/


/** middleware for verify user */
export async function verifyUser(req, res, next){
    try {
        
        const { username } = req.method == "GET" ? req.query : req.body;

        // check the user existance
        let exist = await UserModel.findOne({ username });
        if(!exist) return res.status(404).send({ error : "Can't find User!"});
        next();

    } catch (error) {
        return res.status(404).send({ error: "Authentication Error"});
    }
}

export async function register(req, res) {
    try {
        const { username, password, profile, email } = req.body;

        // Check if the username already exists
        const existingUsername = await UserModel.findOne({ username });
        if (existingUsername) {
            return res.status(400).send({ error: "Please use a unique username" });
        }

        // Check if the email already exists
        const existingEmail = await UserModel.findOne({ email });
        if (existingEmail) {
            return res.status(400).send({ error: "Please use a unique email" });
        }

        // Hash the password
        if (!password) {
            return res.status(400).send({ error: "Password is required" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const user = new UserModel({
            username,
            password: hashedPassword,
            profile: profile || '',
            email,
        });

        // Save the user to the database
        await user.save();

        return res.status(201).send({ msg: "User registered successfully" });
    } catch (error) {
        return res.status(500).send({ error: error.message || "Internal Server Error" });
    }
}

/** GET: http://localhost:8080/api/user/example123 */
export async function login(req, res) {
    const { username, password } = req.body;

    try {
        const user = await UserModel.findOne({ username });
        if (!user) {
            return res.status(404).send({ error: "Username not Found" });
        }

        const passwordCheck = await bcrypt.compare(password, user.password);
        if (!passwordCheck) {
            return res.status(400).send({ error: "Incorrect Password" });
        } 

        // Create JWT token
        const token = jwt.sign({
            userId: user._id,
            username: user.username
        }, ENV.jwt_secret, { expiresIn: "24h" });

        return res.status(200).send({
            msg: "Login Successful!",
            username: user.username,
            token
        });
    } catch (error) {
        return res.status(500).send({ error });
    }
}

export async function getUser(req, res) {
    const { username } = req.params;

    try {
        if (!username) {
            return res.status(501).send({ error: "Invalid Username" });
        }

        const user = await UserModel.findOne({ username });
        if (!user) {
            return res.status(501).send({ error: "Couldn't Find the User" });
        }

        // Remove password from user and convert it into JSON
        const { password, ...rest } = user.toJSON();

        return res.status(201).send(rest);
    } catch (error) {
       return res.status(404).send({ error: "Cannot Find User Data" });
   }
}

/** PUT: http://localhost:8080/api/updateuser 
 * @param: {
  "header" : "<token>"
}
body: {
    firstName: '',
    address : '',
    profile : ''
}
*/
export async function updateUser(req, res) {
    try {
        const { userId } = req.user;

        if (userId) {
            const body = req.body;

            // update the data
            const data = await UserModel.updateOne({ _id: userId }, body);
            return res.status(201).send({ msg: "Record Updated...!" },data);

        } else {
            return res.status(401).send({ error: "User Not Found...!" });
        }

    } catch (error) {
        return res.status(401).send({ error });
    }
}

/** GET: http://localhost:8080/api/generateOTP */
export async function generateOTP(req,res){
    req.app.locals.OTP = await otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false})
    res.status(201).send({ code: req.app.locals.OTP })
}

export async function verifyOTP(req,res){
    const { code } = req.query;
    if(parseInt(req.app.locals.OTP) === parseInt(code)){
        req.app.locals.OTP = null; // reset the OTP value
        req.app.locals.resetSession = true; // start session for reset password
        return res.status(201).send({ msg: 'Verify Successsfully!'})
    }
    return res.status(400).send({ error: "Invalid OTP"});
}

// successfully redirect user when OTP is valid
/** GET: http://localhost:8080/api/createResetSession */
export async function createResetSession(req,res){
   if(req.app.locals.resetSession){
        return res.status(201).send({ flag : req.app.locals.resetSession})
   }
   return res.status(440).send({error : "Session expired!"})
}

export async function resetPassword(req, res) {
    try {
        // Check for reset session validity
        if (!req.app.locals.resetSession) {
            return res.status(440).send({ error: "Session expired!" });
        }

        const { username, password } = req.body;

        try {
            // Find the user by username
            const user = await UserModel.findOne({ username });
            if (!user) {
                return res.status(404).send({ error: "Username not found" });
            }

            // Hash the new password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Update the user's password
            const updatedUser = await UserModel.updateOne(
                { username: user.username },
                { password: hashedPassword }
            );

            // Reset the session
            req.app.locals.resetSession = false;

            return res.status(201).send({ msg: "Record updated!" });
        } catch (error) {
            return res.status(500).send({ error: "An error occurred during the update" });
        }
    } catch (error) {
        return res.status(401).send({ error: "Unauthorized" });
    }
}

export async function Infodetails(req, res) {
    
        try {
            const {  firstName, surName, phone, otherName, country, region, city, degree, email } = req.body;

            // Validate required fields
            if ( !firstName || !surName || !phone || !email || !degree) {
                return res.status(400).json({ error: "Required fields are missing" });
            }

            // Check if email already exists
            const existingUser = await det.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ error: "Email already exists" });
            }

            // Create and save the new user
            const newUser = new det({  firstName, surName, phone, otherName, country, region, city, degree, email });
            await newUser.save();

            return res.status(201).json({ message: "User data stored successfully", data: newUser });
        } catch (error) {
            return res.status(500).json({ error: "Server error", details: error.message });
        }
    }



