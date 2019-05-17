Fork of [oktadelegate](https://github.com/zeekhoo-okta/oktadelegate) that has the jwt-verifier stripped off.
* Required claims are assumed to have been inserted into custom headers.
* This is meant to be run behind an AWS API Gateway that uses a custom [Lambda Authorizer](https://github.com/zeekhoo-okta/oktadelegate-lambda-authorizer) to validate the jwt and inject the claims as custom headers to the API resource. 
