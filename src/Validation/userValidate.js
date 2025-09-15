import Joi from "joi";

const userValidationSchema = Joi.object({
    username: Joi.string().min(3).required(),

    email: Joi.string()
        .email({ tlds: { allow: false } })
        .required(),

    password: Joi.string().min(8).required(),

    isLoggedIn: Joi.boolean().default(false),

    isVerified: Joi.boolean().default(false),

    token: Joi.string().allow(null).optional(),

    otp: Joi.string().allow(null).optional(),

    otpExpiry: Joi.date().allow(null).optional(),
});

const loginValidationSchema = Joi.object({
    email: Joi.string().email({ tlds: { allow: false } }).required(),
    password: Joi.string().required()
});

const passwordCheckValidationSchema = Joi.object({
    newPassword: Joi.string().min(8).required(),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required()
})

export { userValidationSchema, loginValidationSchema, passwordCheckValidationSchema };