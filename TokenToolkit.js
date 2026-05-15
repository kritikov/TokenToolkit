import JWT from "./Core/JWT.js";

export default class TokenToolkit {

     static decodeJWT(jwt) {
            const result = JWT.isValidInput(jwt);

            if (!result.valid) {
                return {
                    valid: false,
                    error: result.error
                };
            }
            else {
                return {
                    valid: true,
                    jwt: new JWT(jwt)
                };
            }
        }

}