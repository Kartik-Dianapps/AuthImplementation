import Joi from "joi";

const userValidationSchema = Joi.object({
    username: Joi.string().required(),

    email: Joi.string()
        .email({ tlds: { allow: false } })
        .required(),

    password: Joi.string().required(),

    isLoggedIn: Joi.boolean().default(false),

    isVerified: Joi.boolean().default(false),

    token: Joi.string().allow(null).optional(),

    otp: Joi.string().allow(null).optional(),

    otpExpiry: Joi.date().allow(null).optional(),
});

export default userValidationSchema;